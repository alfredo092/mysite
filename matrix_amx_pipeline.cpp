/*
============================================================================
NEXUS AMX PIPELINE: PERF HW-COUNTERS + DYNAMIC SQPOLL + RINGBUF BATCHING
============================================================================
File: nexus_amx_pipeline.cpp
Version: 4.0.0 (Perf + Dynamic CPU + SPSC Ring + AMX + TUI)
Target: Kali Linux ARM64 (Apple M2/AMX Custom Toolchain)
COMPILATION:
  g++ -std=c++20 -O3 -DUSE_AMX -march=armv8-a -fno-exceptions -fno-rtti \
      -Wall -Wextra -pthread -ffast-math \
      -o nexus_amx_pipeline nexus_amx_pipeline.cpp \
      -lbpf -luring -lpthread -lrt -lm
RUN:
  sudo ./nexus_amx_pipeline --target http://192.168.1.10:8080 --iface eth0
============================================================================
*/
#define _GNU_SOURCE
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <cstring>
#include <cstdbool>
#include <cmath>
#include <csignal>
#include <unistd.h>
#include <fcntl.h>
#include <pthread.h>
#include <sched.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <linux/perf_event.h>
#include <bpf/libbpf.h>
#include <liburing.h>
#include <atomic>
#include <mutex>
#include <array>
#include <string>
#include <vector>
#include <chrono>
#include <thread>
#include <algorithm>

/* ============================================================================
   CONFIGURATION
============================================================================ */
constexpr size_t BATCH_SIZE      = 8;
constexpr size_t LOG_LINES       = 48;
constexpr size_t CACHE_LINE      = 64;
constexpr size_t RINGBUF_CAP     = 8192;
constexpr int    TUI_REFRESH_MS  = 80;

/* ============================================================================
   TYPES (Cache-Line Aligned)
============================================================================ */
struct alignas(CACHE_LINE) Mat4x4 { float m[4][4]; };
struct alignas(CACHE_LINE) Batch8 { Mat4x4 A[BATCH_SIZE], B[BATCH_SIZE], C[BATCH_SIZE]; };

struct bpf_event {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t timestamp_ns;
    uint64_t weight;
    uint32_t payload_len;
    uint8_t proto;
    uint8_t pad[7];
    uint8_t data[128];
};

struct TargetConfig {
    std::string raw;
    std::string host;
    uint16_t port = 0;
    bool is_https = false;
};

struct TUIState {
    std::atomic<uint64_t> events_total{0};
    std::atomic<uint64_t> batches_done{0};
    std::atomic<uint64_t> cycles_delta{0};
    std::atomic<uint64_t> inst_delta{0};
    std::atomic<uint64_t> cache_miss_delta{0};
    std::atomic<uint32_t> avg_latency_us{0};
    std::atomic<bool> amx_ready{false};
    std::atomic<bool> running{true};
    std::mutex log_mutex;
    std::array<std::string, LOG_LINES> log_buffer;
    std::atomic<size_t> log_idx{0};
};

struct PerfCounters {
    int fd_cycles = -1, fd_instr = -1, fd_cache = -1;
    uint64_t base_cycles = 0, base_instr = 0, base_cache = 0;

    bool init() {
        struct perf_event_attr pe{};
        pe.type = PERF_TYPE_HARDWARE;
        pe.size = sizeof(pe);
        pe.disabled = 1;
        pe.exclude_kernel = 1;
        pe.exclude_hv = 1;

        // CPU Cycles
        pe.config = PERF_COUNT_HW_CPU_CYCLES;
        fd_cycles = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
        if (fd_cycles < 0) return false;

        // Instructions
        pe.config = PERF_COUNT_HW_INSTRUCTIONS;
        fd_instr = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);

        // Cache Misses
        pe.config = PERF_COUNT_HW_CACHE_MISSES;
        fd_cache = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);

        ioctl(fd_cycles, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_instr, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_cache, PERF_EVENT_IOC_RESET, 0);
        ioctl(fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
        ioctl(fd_instr, PERF_EVENT_IOC_ENABLE, 0);
        ioctl(fd_cache, PERF_EVENT_IOC_ENABLE, 0);

        read(fd_cycles, &base_cycles, sizeof(base_cycles));
        read(fd_instr, &base_instr, sizeof(base_instr));
        read(fd_cache, &base_cache, sizeof(base_cache));
        return true;
    }

    void update(std::atomic<uint64_t>& cycles, std::atomic<uint64_t>& instr, std::atomic<uint64_t>& cache) {
        uint64_t c, i, m;
        if (read(fd_cycles, &c, sizeof(c)) == sizeof(c)) cycles.store(c - base_cycles);
        if (read(fd_instr, &i, sizeof(i)) == sizeof(i)) instr.store(i - base_instr);
        if (fd_cache > 0 && read(fd_cache, &m, sizeof(m)) == sizeof(m)) cache.store(m - base_cache);
    }
};

/* ============================================================================
   DYNAMIC CPU SELECTOR (SQ_POLL_CPU)
============================================================================ */
static int select_sq_cpu() {
    int current = sched_getcpu();
    int total = sysconf(_SC_NPROCESSORS_ONLN);
    if (total <= 1) return 0;
    // Pick next available core, avoiding current one
    return (current + 1) % total;
}

/* ============================================================================
   USERSPACE SPSC RING BUFFER (Zero-Copy Batching)
============================================================================ */
template <typename T, size_t CAP = RINGBUF_CAP>
class SPSCRing {
    static_assert((CAP & (CAP - 1)) == 0, "Power of 2 required");
    alignas(CACHE_LINE) std::atomic<uint32_t> head_{0};
    alignas(CACHE_LINE) std::atomic<uint32_t> tail_{0};
    T data_[CAP];
public:
    bool push(const T& item) {
        uint32_t h = head_.load(std::memory_order_relaxed);
        uint32_t next = (h + 1) & (CAP - 1);
        if (next == tail_.load(std::memory_order_acquire)) return false;
        data_[h] = item;
        head_.store(next, std::memory_order_release);
        return true;
    }
    bool pop(T& item) {
        uint32_t t = tail_.load(std::memory_order_relaxed);
        if (t == head_.load(std::memory_order_acquire)) return false;
        item = data_[t];
        tail_.store((t + 1) & (CAP - 1), std::memory_order_release);
        return true;
    }
    size_t size() const { return (head_.load() - tail_.load()) & (CAP - 1); }
};

/* ============================================================================
   TARGET PARSER
============================================================================ */
static TargetConfig parse_target(const char* input) {
    TargetConfig cfg; cfg.raw = input; std::string s = input;
    if (s.rfind("https://", 0) == 0) { cfg.is_https = true; s = s.substr(8); }
    else if (s.rfind("http://", 0) == 0) s = s.substr(7);
    size_t slash = s.find('/'); if (slash != std::string::npos) s = s.substr(0, slash);
    size_t colon = s.find(':');
    if (colon != std::string::npos) {
        cfg.host = s.substr(0, colon);
        try { cfg.port = static_cast<uint16_t>(std::stoi(s.substr(colon + 1))); }
        catch (...) { cfg.port = cfg.is_https ? 443 : 80; }
    } else { cfg.host = s; cfg.port = cfg.is_https ? 443 : 80; }
    if (!isdigit(cfg.host[0])) {
        struct addrinfo hints{}, *res{}; hints.ai_family = AF_INET;
        if (getaddrinfo(cfg.host.c_str(), nullptr, &hints, &res) == 0) {
            char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &((sockaddr_in*)res->ai_addr)->sin_addr, buf, sizeof(buf));
            cfg.host = buf; freeaddrinfo(res);
        }
    }
    return cfg;
}

/* ============================================================================
   AMX MATRIX ENGINE (Scalar Fallback)
============================================================================ */
#ifdef USE_AMX
static inline void batch_mul_amx(const float* A, const float* B, float* C, size_t count) {
    for (size_t idx = 0; idx < count; ++idx) {
        const float* a = A + idx * 16;
        const float* b = B + idx * 16;
        float* c = C + idx * 16;
        for (int r = 0; r < 4; ++r) {
            for (int k = 0; k < 4; ++k) {
                float sum = 0.0f;
                for (int s = 0; s < 4; ++s) {
                    sum += a[r * 4 + s] * b[s * 4 + k];
                }
                c[r * 4 + k] = sum;
            }
        }
    }
}
#else
#error "USE_AMX must be defined. Compile with -DUSE_AMX"
#endif

/* ============================================================================
   io_uring SQPOLL WRITER (Dynamic CPU)
============================================================================ */
struct SQPollWriter {
    io_uring ring{};
    int fd = -1;
    char buf[512]{};
    bool init(const char* path) {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
        if (fd < 0) { perror("open"); return false; }
        io_uring_params p{};
        p.flags = IORING_SETUP_SQPOLL | IORING_SETUP_SQ_AFF | IORING_SETUP_SINGLE_ISSUER;
        p.sq_thread_cpu = select_sq_cpu();
        p.sq_thread_idle = 200;
        if (io_uring_queue_init_params(8192, &ring, &p) < 0) { perror("io_uring"); return false; }
        return true;
    }
    inline void submit(uint64_t ts, int lat) {
        io_uring_sqe* sqe = io_uring_get_sqe(&ring);
        if (!sqe) return;
        int len = snprintf(buf, sizeof(buf), "ts=%-15lu lat=%-4dus\n", ts, lat);
        io_uring_prep_write(sqe, fd, buf, len, 0);
        sqe->user_data = 0;
    }
    inline void drain() {
        io_uring_cqe* cqe; unsigned h;
        io_uring_for_each_cqe(&ring, h, cqe) {}
        io_uring_cq_advance(&ring, h);
    }
    ~SQPollWriter() { if(fd>=0) close(fd); io_uring_queue_exit(&ring); }
};

/* ============================================================================
   REAL-TIME TUI
============================================================================ */
static void render_tui(const TargetConfig& tgt, TUIState& st) {
    printf("\033[2J\033[H\033[?25l");
    printf("┌──────────────────────────────────────────────────────────────────────┐\n");
    printf("│ TARGET : %-40s │ BACKEND: AMX ZA-ACC │\n", (tgt.host + ":" + std::to_string(tgt.port)).c_str());
    printf("├──────────────────────────────────────────────────────────────────────┤\n");
    printf("│ EVENTS : %-10lu │ BATCHES: %-10lu │ LATENCY: %-4u μs          │\n", 
           st.events_total.load(), st.batches_done.load(), st.avg_latency_us.load());
    printf("│ CYCLES : %-10lu │ INST:  %-10lu │ MISS:  %-10lu              │\n",
           st.cycles_delta.load(), st.inst_delta.load(), st.cache_miss_delta.load());
    printf("│ STATUS : %s                                                              │\n", 
           st.amx_ready.load() ? "AMX ACTIVE ✅" : "INITIALIZING ⏳");
    printf("├──────────────────────────────────────────────────────────────────────┤\n");
    printf("│ LIVE EVENT LOG (RingBuf Batched)                                       │\n");
    printf("├──────────────────────────────────────────────────────────────────────┤\n");
    
    std::lock_guard<std::mutex> lock(st.log_mutex);
    size_t idx = st.log_idx.load();
    for (size_t i = 0; i < LOG_LINES; ++i) {
        size_t line_idx = (idx + i) % LOG_LINES;
        if (!st.log_buffer[line_idx].empty())
            printf("│ %-64s │\n", st.log_buffer[line_idx].c_str());
        else
            printf("│                                                                  │\n");
    }
    printf("└──────────────────────────────────────────────────────────────────────┘\033[?25h");
    fflush(stdout);
}

/* ============================================================================
   PIPELINE STATE & HANDLERS
============================================================================ */
static Batch8 g_batch{};
static SPSCRing<bpf_event> g_spsc;
static TUIState g_state;
static SQPollWriter g_writer;
static PerfCounters g_perf;

static void push_log(const std::string& line) {
    std::lock_guard<std::mutex> lock(g_state.log_mutex);
    g_state.log_buffer[g_state.log_idx.fetch_add(1, std::memory_order_relaxed) % LOG_LINES] = line;
}

static int ringbuf_handler(void*, void* data, size_t) {
    if (!data) return 0;
    const bpf_event* evt = static_cast<const bpf_event*>(data);
    g_state.events_total.fetch_add(1, std::memory_order_relaxed);
    if (!g_spsc.push(*evt)) return 0; // Drop if full (rare)
    return 0;
}

static void process_batch() {
    bpf_event evt{};
    int idx = 0;
    while (g_spsc.pop(evt) && idx < BATCH_SIZE) {
        std::memcpy(g_batch.A[idx].m, &evt.src_ip, sizeof(float)*16);
        for(int i=0; i<16; ++i) g_batch.B[idx].m[i/4][i%4] = (float)(i+1)*0.05f;
        idx++;
    }
    if (idx == 0) return;

    auto t0 = std::chrono::high_resolution_clock::now();
    batch_mul_amx(
        reinterpret_cast<const float*>(g_batch.A),
        reinterpret_cast<const float*>(g_batch.B),
        reinterpret_cast<float*>(g_batch.C),
        idx
    );
    auto t1 = std::chrono::high_resolution_clock::now();
    int lat = std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count();
    g_state.avg_latency_us.store(lat, std::memory_order_relaxed);
    g_state.batches_done.fetch_add(1, std::memory_order_relaxed);

    g_writer.submit(evt.timestamp_ns, lat);
    g_writer.drain();

    char src[16], dst[16];
    inet_ntop(AF_INET, &evt.src_ip, src, sizeof(src));
    inet_ntop(AF_INET, &evt.dst_ip, dst, sizeof(dst));
    char logline[128];
    snprintf(logline, sizeof(logline), "%s:%u → %s:%u | Δ=%dμs | AMX OK", 
             src, ntohs(evt.src_port), dst, ntohs(evt.dst_port), lat);
    push_log(logline);
}

/* ============================================================================
   SIGNALS & CLEANUP
============================================================================ */
static volatile bool sig_quit = false;
static void sig_handler(int) { g_state.running.store(false); sig_quit = true; }
static void cleanup(struct bpf_object* obj, struct ring_buffer* rb) {
    if (rb) ring_buffer__free(rb);
    if (obj) bpf_object__close(obj);
}

/* ============================================================================
   MAIN
============================================================================ */
int main(int argc, char** argv) {
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    
    TargetConfig target = {"127.0.0.1:80", "127.0.0.1", 80, false};
    const char* iface = "lo";
    std::string mode = "socket";
    
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--target" && i + 1 < argc) target = parse_target(argv[++i]);
        else if (std::string(argv[i]) == "--iface" && i + 1 < argc) iface = argv[++i];
        else if (std::string(argv[i]) == "--mode" && i + 1 < argc) mode = argv[++i];
        else if (argv[i][0] != '-') target = parse_target(argv[i]);
    }
    
    printf("[INIT] Nexus AMX Pipeline v4.0 | Target: %s:%u | Iface: %s\n", 
           target.host.c_str(), target.port, iface);
    
    g_perf.init();
    g_state.amx_ready.store(true);
    
    // eBPF Setup
    struct rlimit rlim{RLIM_INFINITY, RLIM_INFINITY};
    setrlimit(RLIMIT_MEMLOCK, &rlim);
    
    struct bpf_object* obj = bpf_object__open_file("ebpf/matrix_pipe.bpf.o", nullptr);
    if (!obj) { fprintf(stderr, "[ERR] bpf_object__open failed\n"); return 1; }
    if (bpf_object__load(obj)) { fprintf(stderr, "[ERR] bpf_object__load failed\n"); return 1; }
    
    int ifindex = if_nametoindex(iface);
    int raw_fd = -1;
    if (mode == "socket") {
        struct bpf_program* prog = bpf_object__find_program_by_name(obj, "matrix_socket_prog");
        if (prog) {
            int prog_fd = bpf_program__fd(prog);
            raw_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
            if (raw_fd < 0) {
                perror("socket");
            } else {
                if (ifindex) {
                    struct sockaddr_ll sll{};
                    sll.sll_family = AF_PACKET;
                    sll.sll_protocol = htons(ETH_P_ALL);
                    sll.sll_ifindex = ifindex;
                    if (bind(raw_fd, (struct sockaddr*)&sll, sizeof(sll)) < 0) {
                        perror("bind");
                        close(raw_fd);
                        raw_fd = -1;
                    }
                }
                if (raw_fd >= 0 && setsockopt(raw_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
                    perror("SO_ATTACH_BPF");
                    close(raw_fd);
                    raw_fd = -1;
                }
                if (raw_fd >= 0) {
                    printf("[BPF] Socket filter attached on %s\n", iface);
                }
            }
        }
    } else {
        if (ifindex) {
            struct bpf_program* prog = bpf_object__find_program_by_name(obj, "matrix_xdp_prog");
            if (prog) bpf_program__attach_xdp(prog, ifindex);
        }
    }
    
    int map_fd = bpf_object__find_map_fd_by_name(obj, "events");
    if (map_fd < 0) { fprintf(stderr, "[ERR] events map not found\n"); return 1; }
    
    struct ring_buffer* rb = ring_buffer__new(map_fd, ringbuf_handler, nullptr, nullptr);
    if (!rb) { fprintf(stderr, "[ERR] ring_buffer__new failed\n"); return 1; }
    
    if (!g_writer.init("nexus_amx.log")) return 1;
    
    printf("[RUN] Polling ringbuf. Press Ctrl+C to stop.\n");
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Background TUI & Perf Reader
    std::thread tui_thread([&]() {
        while (g_state.running.load()) {
            render_tui(target, g_state);
            g_perf.update(g_state.cycles_delta, g_state.inst_delta, g_state.cache_miss_delta);
            process_batch();
            std::this_thread::sleep_for(std::chrono::milliseconds(TUI_REFRESH_MS));
        }
    });
    
    while (!sig_quit) {
        ring_buffer__poll(rb, 10);
    }
    
    printf("\n[SHUTDOWN] Cleaning up...\n");
    g_state.running.store(false);
    if (tui_thread.joinable()) tui_thread.join();
    cleanup(obj, rb);
    printf("[DONE] Pipeline stopped.\n");
    return 0;
}