/*
============================================================================
PEC MATRIX ENGINE: TARGET + TUI + PERF + AMX/NEON/SME2 (C11 Fixed)
============================================================================
File: pec_matrix_engine.c
Version: 1.9.2 (C11 Compliant + Target Parser + Live TUI + perf_event_open)
Target: Kali Linux ARM64 / Apple M2 (Asahi/VM) / ARMv8.2+
COMPILATION:
  clang -O3 -std=c11 -Wall -Wextra -pthread -ffast-math -fslp-vectorize -mcpu=native \
      -o pec_matrix_engine pec_matrix_engine.c -lpthread -lrt -lbpf -lssl -lcrypto -lm
RUN:
  sudo ./pec_matrix_engine --target http://192.168.1.10:8080 eth0
============================================================================
*/
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdbool.h>
#include <string.h>
#include <stdatomic.h>
#include <math.h>
#include <unistd.h>
#include <fcntl.h>
#include <signal.h>
#include <pthread.h>
#include <sched.h>
#include <time.h>
#include <errno.h>
#include <inttypes.h>
#include <sys/auxv.h>
#include <sys/mman.h>
#include <sys/eventfd.h>
#include <sys/socket.h>
#include <sys/shm.h>
#include <sys/ioctl.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include <arpa/inet.h>
#include <netinet/tcp.h>
#include <strings.h>
#include <netdb.h>
#include <net/if.h>
#include <ctype.h>
#include <ifaddrs.h>
#include <stdarg.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/hmac.h>
#include <linux/capability.h>
#include <linux/if_link.h>
#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/perf_event.h>
#include <sys/resource.h>
#include <limits.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#ifdef __linux__
#include <asm/hwcap.h>
#endif
#if defined(__ARM_NEON) || defined(__aarch64__)
#include <arm_neon.h>
#endif
#ifdef __ARM_FEATURE_SVE
#include <arm_sve.h>
#endif

#define MAX_PARSER_BUF 65536

static void safe_snprintf(char *dst, size_t dst_size, const char *fmt, ...) {
    if (!dst || dst_size == 0) return;
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(dst, dst_size, fmt, ap);
    va_end(ap);
    dst[dst_size - 1] = '\0';
}

static char *safe_strncpy(char *dst, const char *src, size_t n) {
    if (!dst || n == 0) return dst;
    if (!src) {
        dst[0] = '\0';
        return dst;
    }
    size_t i = 0;
    while (i + 1 < n && src[i]) {
        dst[i] = src[i];
        i++;
    }
    dst[i] = '\0';
    return dst;
}

#define snprintf safe_snprintf
#define strncpy safe_strncpy

/* ============================================================================
   CONFIGURATION (OPTIMIZED FOR HFT SOLUSDT VIA EBPF)
============================================================================ */
#define PEC_VIRTUAL_CHANNELS    1024
#define PHASE_DIM               64
#define INTERFERENCE_CYCLES     16
#define COLLAPSE_THRESH         0.42f
#define ADAPTIVE_THRESH_MIN     0.28f
#define ADAPTIVE_THRESH_MAX     0.72f
#define ADAPTIVE_DRIFT_RATE     0.045f
#define ADAPTIVE_LEARN_RATE     0.0125f
#define SEARCH_COMPRESSION      1e5f
#define ENERGY_PER_COLLAPSE_J   0.115f
#define RTX4090_TH_PER_CARD     0.85f
#define DEFAULT_PEC_WORKER_THREADS 4

/* Системные тайминги: Переводим RingBuf в режим агрессивного наносекундного ожидания */
#define DEFAULT_RINGBUF_POLL_MS    0
#define DEFAULT_PEC_SLEEP_MIN_MS   0
#define DEFAULT_PEC_SLEEP_MAX_MS   1
#define DEFAULT_UI_UPDATE_MS     250
#define UPDATE_INTERVAL_MS       150
#define THREAD_PIN_DELAY_US      500
#define INTERNAL_LATENCY_ALERT_US 50

/* Защита от бана Bybit API V5 (Rate Limits) */
#define SNIPE_RATE_LIMIT_MAX       5
#define SNIPE_RATE_LIMIT_WINDOW_NS (10ULL * 1000000000ULL)
#define DEFAULT_BYBIT_LATENCY_MS  50.0f
#define DEFAULT_BOT_COOLDOWN_SEC    3

/* Боевые HFT параметры скальпинга SOLUSDT */
#define SNIPER_TRADE_COOLDOWN_MS       3000ULL
#define SNIPER_MIN_BOOK_VOLUME         500.0f
#define SNIPER_MIN_PROFIT_TO_EXIT_PCT  0.18f
#define SNIPER_EMERGENCY_STOP_LOSS_PCT 0.25f
#define DEFAULT_BOT_SLIPPAGE_PCT       0.1f

/* Системная обвязка */
#define SHM_NAME                "photonic_solana_status"
#define SHM_SIZE                4096
#define TUI_LINES               48
#define TARGET_MAX_LEN          256
#define BPF_STATS_MAP_PATH      "/sys/fs/bpf/pec_event_metrics"
#define METRIC_RINGBUF_FULL     0

/* ============================================================================
   TYPES
============================================================================ */
typedef enum { COLLAPSE_IDLE, COLLAPSE_PENDING, COLLAPSE_VERIFIED, COLLAPSE_SUBMITTED, COLLAPSE_FAILED } collapse_state_t;
typedef enum { BACKEND_SME2, BACKEND_AMX, BACKEND_NEON, BACKEND_SCALAR } matrix_backend_t;
typedef enum { ACT_NONE, ACT_BUY, ACT_SELL, ACT_SHORT, ACT_COVER } bot_action_t;

typedef struct __attribute__((aligned(64))) {
    _Atomic uint32_t state;
    uint64_t collapse_id;
    float coherence;
    uint32_t phase_hash;
    uint64_t timestamp_ns;
    char signature[128];
    uint64_t last_updated_ns;
} pec_status_t;

typedef struct __attribute__((aligned(64))) {
    float phase_state[PHASE_DIM];
    float amplitude[PHASE_DIM];
    float interference_map[PHASE_DIM * PHASE_DIM];
    uint64_t collapses;
    uint64_t cycles;
    float last_coherence;
    float last_peak;
    float adaptive_thresh;
    float threshold_drift;
    uint8_t _pad[16];
} pec_channel_t;

typedef struct {
    char target[TARGET_MAX_LEN];
    char host[128];
    char hostname[128];
    char path[128];
    uint16_t port;
    bool is_https;
} target_config_t;

typedef struct {
    _Atomic uint64_t events_total;
    _Atomic uint64_t batches_done;
    _Atomic uint64_t cycles_delta;
    _Atomic uint64_t inst_delta;
    _Atomic uint64_t cache_miss_delta;
    _Atomic uint64_t dropped_ringbuf;
    _Atomic uint64_t partial_invalid;
    _Atomic uint64_t e2e_latency_last_ns;
    _Atomic uint64_t e2e_latency_total_ns;
    _Atomic uint64_t e2e_latency_count;
    _Atomic uint64_t internal_latency_last_ns;
    _Atomic uint64_t internal_latency_total_ns;
    _Atomic uint64_t internal_latency_count;
    _Atomic float peak_resonance;
    _Atomic bool running;
    char log_buffer[TUI_LINES][256];
    char last_event[128];
    char startup_message[128];
    bool header_printed;
    _Atomic size_t log_idx;
    pthread_mutex_t log_mutex;
} tui_state_t;

typedef struct {
    int fd_cycles, fd_instr, fd_cache;
    uint64_t base_cycles, base_instr, base_cache;
} perf_counters_t;

#define EVENT_TYPE_NORMAL 0
#define EVENT_TYPE_HEARTBEAT 1
#define EVENT_TYPE_SSL_READ 2
#define EVENT_TYPE_SSL_WRITE 3
#define EVENT_TYPE_SSL_READ_EX 4
#define EVENT_TYPE_SSL_WRITE_EX 5
#define EVENT_TYPE_SSL_WRITE_EX2 6
#define EVENT_TYPE_SSL_WRITE_EARLY 7
#define EVENT_TYPE_SSL_READ_EARLY 8
#define EVENT_TYPE_SYSCALL_SEND 9

/* BPF event — MUST match ebpf/matrix_pipe.bpf.c */
struct matrix_event {
    uint32_t src_ip, dst_ip;
    uint16_t src_port, dst_port;
    uint64_t timestamp;
    uint64_t weight;
    uint32_t payload_len;
    uint8_t proto_hint;
    uint8_t event_type;
    uint8_t _pad[30];
    uint8_t data[MAX_PARSER_BUF];
} __attribute__((aligned(64)));

/* ============================================================================
   GLOBALS
============================================================================ */
static matrix_backend_t g_backend;
static pec_channel_t g_channels[PEC_VIRTUAL_CHANNELS];
static _Atomic uint64_t g_total_collapses = 0;
static _Atomic float g_peak_resonance = 0.0f;
static _Atomic uint64_t g_ssl_read_events = 0;
static _Atomic uint64_t g_ssl_write_events = 0;
static _Atomic uint64_t g_ssl_read_ex_events = 0;
static _Atomic uint64_t g_ssl_write_ex_events = 0;
static _Atomic uint64_t g_ssl_write_ex2_events = 0;
static _Atomic uint64_t g_ssl_write_early_events = 0;
static _Atomic uint64_t g_ssl_read_early_events = 0;
static _Atomic bool g_running = true;
static pec_status_t *g_shm = NULL;
static int g_shm_fd = -1, g_eventfd = -1, g_ringbuf_fd = -1;
static struct ring_buffer *g_ringbuf = NULL;
static int g_bpf_stats_fd = -1;
static struct bpf_object *g_bpf_obj = NULL;
static int g_bpf_sock_fd = -1;
static SSL_CTX *g_ssl_ctx = NULL;
static struct bpf_link *g_bpf_ssl_read_link = NULL;
static struct bpf_link *g_bpf_ssl_write_link = NULL;
static struct bpf_link *g_bpf_ssl_read_ex_link = NULL;
static struct bpf_link *g_bpf_ssl_write_ex_link = NULL;
static struct bpf_link *g_bpf_ssl_read_entry_link = NULL;
static struct bpf_link *g_bpf_ssl_write_entry_link = NULL;
static struct bpf_link *g_bpf_ssl_read_ex_entry_link = NULL;
static struct bpf_link *g_bpf_ssl_write_ex_entry_link = NULL;
static const char *g_bpf_iface = "";
static const char *g_bpf_mode = "socket";
static const char *g_bpf_ssl_binary = "/usr/lib/aarch64-linux-gnu/libssl.so.3";

static size_t g_bpf_ssl_read_offset = 0x3fa00;

/* BPF/SSL Control Globals */
static bool g_bpf_god_mode = true;
static _Atomic bool g_bpf_ssl_read_attached = false;
static _Atomic bool g_bpf_ssl_write_attached = false;
static _Atomic bool g_bpf_ssl_read_ex_attached = false;
static _Atomic bool g_bpf_ssl_write_ex_attached = false;
static size_t g_bpf_ssl_write_offset = 0x3fdb0;
static size_t g_bpf_ssl_read_ex_offset = 0x40560;
static size_t g_bpf_ssl_write_ex_offset = 0x40820;
static __attribute__((unused)) size_t g_bpf_ssl_write_ex2_offset = 0x41080;
static __attribute__((unused)) size_t g_bpf_ssl_read_early_data_offset = 0x41340;
static __attribute__((unused)) size_t g_bpf_ssl_write_early_data_offset = 0x41600;

/* Configuration Globals */
static uint32_t g_worker_threads = DEFAULT_PEC_WORKER_THREADS;
static int g_tui_update_ms = DEFAULT_UI_UPDATE_MS;
static int g_ringbuf_poll_ms = DEFAULT_RINGBUF_POLL_MS;
static int g_pec_sleep_min_ms = DEFAULT_PEC_SLEEP_MIN_MS;
static int g_pec_sleep_max_ms = DEFAULT_PEC_SLEEP_MAX_MS;
static int g_sq_poll_cpu = -1;
static bool g_raw_stream_log = false;
static tui_state_t g_tui = {0};
static target_config_t g_target = {0};
static perf_counters_t g_perf = {0};
static int g_bybit_ws_sock = -1;
static SSL *g_bybit_ws_ssl = NULL;
static const char g_bybit_ws_host[] = "stream.bybit.com";
static const char *g_bybit_ws_paths[] = { "/v5/public/spot", "/v5/public/linear", "/realtime_public", "/realtime", NULL };
static const char *g_allowed_hft_symbols[] = {
    "SOLUSDT",
    "BTCUSDT",
    "ETHUSDT",
    "AVAXUSDT",
    "LINKUSDT",
    "SUIUSDT",
    "NEARUSDT",
    "XRPUSDT",
    "XLMUSDT",
};
#define ALLOWED_SYMBOLS_COUNT (sizeof(g_allowed_hft_symbols) / sizeof(g_allowed_hft_symbols[0]))
static const char g_bybit_ws_subscribe_spot[] =
    "{\"op\":\"subscribe\",\"req_id\":\"amx_multi_01\",\"args\":["
    "\"orderbook.1.SOLUSDT\",\"orderbook.1.BTCUSDT\",\"orderbook.1.ETHUSDT\","
    "\"orderbook.1.AVAXUSDT\",\"orderbook.1.LINKUSDT\",\"orderbook.1.SUIUSDT\","
    "\"orderbook.1.NEARUSDT\",\"orderbook.1.XRPUSDT\",\"orderbook.1.XLMUSDT\""
    "]}";
static const char g_bybit_ws_subscribe_linear[] =
    "{\"op\":\"subscribe\",\"req_id\":\"pec_matrix_01\",\"args\":["
    "\"orderbook.1.SOLUSDT\",\"orderbook.1.BTCUSDT\",\"orderbook.1.ETHUSDT\""
    "]}";
static const char g_bybit_ws_key[] = "x3JJHMbDL1EzLkh9GBhXDw==";

/* MULTITOKEN HFT CONFIGURATION & STATE */
// Фильтр китовой стены в долларах (весить должна не менее $25 000)
#define MIN_WHALE_WALL_USDT 25000.0

typedef struct {
    char symbol[16];
    _Atomic bool position_open;
    _Atomic bot_action_t action;
    _Atomic uint64_t entry_price_bits;
    uint64_t last_trade_ns;
    char last_trade_qty_str[32];
} token_state_t;

static token_state_t g_token_states[ALLOWED_SYMBOLS_COUNT];

static void init_multitoken_states(void) {
    for (size_t i = 0; i < ALLOWED_SYMBOLS_COUNT; i++) {
        safe_strncpy(g_token_states[i].symbol, g_allowed_hft_symbols[i], sizeof(g_token_states[i].symbol));
        atomic_store(&g_token_states[i].position_open, false);
        atomic_store(&g_token_states[i].action, ACT_NONE);
        atomic_store(&g_token_states[i].entry_price_bits, 0);
        g_token_states[i].last_trade_ns = 0;
        memset(g_token_states[i].last_trade_qty_str, 0, sizeof(g_token_states[i].last_trade_qty_str));
    }
}

static inline int find_token_index(const char *symbol) {
    for (int i = 0; i < (int)ALLOWED_SYMBOLS_COUNT; i++) {
        if (strcmp(symbol, g_token_states[i].symbol) == 0) return i;
    }
    return -1;
}

/* Bot/Trading Control Globals */
static _Atomic bool g_sniper_bot_enabled = false;
static _Atomic bool g_anti_rug_enabled = false;
static _Atomic bool g_mev_protection_enabled = false;
static _Atomic bool g_copy_trading_enabled = false;
static _Atomic bool g_auto_snipe_enabled = true;

/* Bot API/Keys */
static char g_bot_api_key[256] = "";
static char g_bot_api_secret[256] = "";
static char g_copy_wallet[256] = "";
static char g_bybit_presigned_tx[4096] = "";

/* Target Contract Info */
static char g_bot_target_contract[128] = "";
static size_t g_bot_target_contract_len = 0;
static char g_bot_event_signature[128] = "";
static size_t g_bot_event_signature_len = 0;

/* Bybit Parameters */
static float g_bybit_max_price_usdt = 250.0f;
static float g_bybit_min_liquidity = 500.0f;
static float g_bybit_min_whale_wall_usdt = 25000.0f;
static __attribute__((unused)) float g_bybit_min_price_change_pct = 0.5f;
static __attribute__((unused)) float g_bybit_max_price_change_pct = 5.0f;
static __attribute__((unused)) float g_bybit_order_size_ratio = 0.1f;
static __attribute__((unused)) float g_bybit_latency_threshold_ms = DEFAULT_BYBIT_LATENCY_MS;
static __attribute__((unused)) float g_bybit_order_spread_bps = 10.0f;
static __attribute__((unused)) float g_bybit_min_order_value_usdt = 1.0f;
static float g_bybit_score_threshold = 0.7f;
static float g_bybit_price_delta_pct = 0.1f;
static float g_bybit_imbalance_ratio = 1.5f;
static float g_bybit_exit_imbalance_ratio = 2.0f;
static float g_bybit_internal_latency_spike_ms = 50.0f;
static float g_bybit_latency_tolerance_ms = DEFAULT_BYBIT_LATENCY_MS;

/* Trading State (HFT Scalping Limits) */
static _Atomic bool g_bot_position_open = false;
static _Atomic uint64_t g_bot_entry_price = 0;
static _Atomic uint64_t g_bot_entry_ns = 0;
static _Atomic uint64_t g_bot_last_trade_ns = 0;
static uint64_t g_bot_trade_cooldown_ns = 3000000000ULL;
static float g_bot_slippage_pct = 0.1f;
static float g_bot_take_profit_pct = 0.18f;
static float g_bot_stop_loss_pct = 0.25f;
static float g_sniper_trade_usdt = 4.0f;

/* Price Tracking */
static _Atomic uint64_t g_last_sol_spot_price = 0;
static _Atomic uint64_t g_last_sol_perp_price = 0;

/* Bot Metrics */
static _Atomic uint64_t g_bot_events_detected = 0;
static _Atomic uint64_t g_bot_actions = 0;

/* Orderbook State */
static _Atomic uint64_t g_bybit_best_bid_price_bits = 0;
static _Atomic uint64_t g_bybit_best_bid_qty_bits = 0;
static _Atomic uint64_t g_bybit_best_ask_price_bits = 0;
static _Atomic uint64_t g_bybit_best_ask_qty_bits = 0;
static _Atomic uint64_t g_solusdt_best_bid_price_bits = 0;
static _Atomic uint64_t g_solusdt_best_bid_qty_bits = 0;
static _Atomic uint64_t g_solusdt_best_ask_price_bits = 0;
static _Atomic uint64_t g_solusdt_best_ask_qty_bits = 0;

/* Settings */
static bool g_bybit_keepalive = true;
static bool g_amx_warmup_enabled = true;
static _Atomic bool g_bot_direct_splice = false;
static _Atomic bool g_bot_wormhole = false;
static _Atomic bool g_bot_x11_stealth = false;

/* Forward Declarations */
static bool path_accessible(const char *path);
static size_t env_size(const char *name, size_t def);
static float env_f32(const char *name, float def);
static bool is_valid_bpf_mode(const char *mode);
static void push_log(const char *msg);
static struct bpf_program *find_bpf_program(struct bpf_object *obj, const char *const names[], size_t name_count);
static struct bpf_link *attach_uprobe_prog_by_program(struct bpf_program *prog, const char *binary_path, size_t func_offset, const char *desc, bool retprobe);
static void parse_pattern_arg(const char *input, uint8_t *output, size_t *out_len, size_t max_len);
static uint64_t monotonic_ns(void);
static bool bot_orderbook_imbalance(double bid_qty, double ask_qty, float ratio);
static bool bot_orderbook_weakness(double bid_qty, double ask_qty, float ratio);
static bool bot_internal_latency_spike(void);
static inline void matrix_outer_product(float *C, const float *A, const float *B, uint32_t dim);
static bool load_event_phase_vectors(float *A, float *B, const struct matrix_event *evt, uint32_t dim);
static const char *resolve_ssl_library_path(const char *requested);
static inline bool bpf_log_is_event(const char *msg);
static inline void photon_virtualization_collapse(float *C, const float *A, const float *B, uint32_t dim);

static void attach_bpf_ssl_uprobes(struct bpf_object *obj) {
    if (!g_bpf_god_mode || !obj) return;
    if (!g_bpf_ssl_read_offset && !g_bpf_ssl_write_offset && !g_bpf_ssl_read_ex_offset && !g_bpf_ssl_write_ex_offset) return;

    const char *binary = getenv("NEXUS_SSL_LIB_PATH");
    if (!binary || !*binary) binary = getenv("PEC_SSL_LIB_PATH");
    if (!binary || !*binary) binary = getenv("NEXUS_BPF_SSL_BINARY");
    if (!binary || !*binary) binary = getenv("PEC_BPF_SSL_BINARY");
    g_bpf_ssl_binary = resolve_ssl_library_path(binary && *binary ? binary : g_bpf_ssl_binary);

    atomic_store(&g_bpf_ssl_read_attached, false);
    atomic_store(&g_bpf_ssl_write_attached, false);
    atomic_store(&g_bpf_ssl_read_ex_attached, false);
    atomic_store(&g_bpf_ssl_write_ex_attached, false);

    const char *ssl_read_entry_names[] = {"SSL_read_entry", "uprobe/SSL_read", "SSL_read_uprobe", "SSL_read"};
    struct bpf_program *ssl_read_entry_prog = find_bpf_program(obj, ssl_read_entry_names, sizeof(ssl_read_entry_names) / sizeof(ssl_read_entry_names[0]));
    if (ssl_read_entry_prog) {
        g_bpf_ssl_read_entry_link = attach_uprobe_prog_by_program(ssl_read_entry_prog, g_bpf_ssl_binary, g_bpf_ssl_read_offset, "SSL_read entry", false);
        if (g_bpf_ssl_read_entry_link) atomic_store(&g_bpf_ssl_read_attached, true);
    } else {
        printf("[BPF] WARNING: SSL_read entry probe not found in BPF object\n");
    }

    const char *ssl_read_names[] = {"SSL_read_retprobe", "uretprobe/SSL_read", "SSL_read_ret"};
    struct bpf_program *ssl_read_prog = find_bpf_program(obj, ssl_read_names, sizeof(ssl_read_names) / sizeof(ssl_read_names[0]));
    if (ssl_read_prog) {
        g_bpf_ssl_read_link = attach_uprobe_prog_by_program(ssl_read_prog, g_bpf_ssl_binary, g_bpf_ssl_read_offset, "SSL_read", true);
        if (g_bpf_ssl_read_link) atomic_store(&g_bpf_ssl_read_attached, true);
    } else {
        printf("[BPF] WARNING: SSL_read return probe not found in BPF object\n");
    }

    const char *ssl_write_entry_names[] = {"SSL_write_entry", "uprobe/SSL_write", "SSL_write_uprobe", "SSL_write"};
    struct bpf_program *ssl_write_entry_prog = find_bpf_program(obj, ssl_write_entry_names, sizeof(ssl_write_entry_names) / sizeof(ssl_write_entry_names[0]));
    if (ssl_write_entry_prog) {
        g_bpf_ssl_write_entry_link = attach_uprobe_prog_by_program(ssl_write_entry_prog, g_bpf_ssl_binary, g_bpf_ssl_write_offset, "SSL_write entry", false);
        if (g_bpf_ssl_write_entry_link) atomic_store(&g_bpf_ssl_write_attached, true);
    }

    const char *ssl_write_names[] = {"SSL_write_retprobe", "uretprobe/SSL_write", "SSL_write_ret"};
    struct bpf_program *ssl_write_prog = find_bpf_program(obj, ssl_write_names, sizeof(ssl_write_names) / sizeof(ssl_write_names[0]));
    if (ssl_write_prog) {
        g_bpf_ssl_write_link = attach_uprobe_prog_by_program(ssl_write_prog, g_bpf_ssl_binary, g_bpf_ssl_write_offset, "SSL_write", true);
        if (g_bpf_ssl_write_link) atomic_store(&g_bpf_ssl_write_attached, true);
    } else {
        printf("[BPF] WARNING: SSL_write return probe not found in BPF object\n");
    }

    const char *ssl_read_ex_entry_names[] = {"SSL_read_ex_entry", "uprobe/SSL_read_ex", "SSL_read_ex_uprobe", "SSL_read_ex"};
    struct bpf_program *ssl_read_ex_entry_prog = find_bpf_program(obj, ssl_read_ex_entry_names, sizeof(ssl_read_ex_entry_names) / sizeof(ssl_read_ex_entry_names[0]));
    if (ssl_read_ex_entry_prog) {
        g_bpf_ssl_read_ex_entry_link = attach_uprobe_prog_by_program(ssl_read_ex_entry_prog, g_bpf_ssl_binary, g_bpf_ssl_read_ex_offset, "SSL_read_ex entry", false);
    } else {
        printf("[BPF] WARNING: SSL_read_ex entry probe not found in BPF object\n");
    }

    const char *ssl_read_ex_names[] = {"SSL_read_ex_retprobe", "uretprobe/SSL_read_ex", "SSL_read_ex_ret"};
    struct bpf_program *ssl_read_ex_prog = find_bpf_program(obj, ssl_read_ex_names, sizeof(ssl_read_ex_names) / sizeof(ssl_read_ex_names[0]));
    if (ssl_read_ex_prog) {
        g_bpf_ssl_read_ex_link = attach_uprobe_prog_by_program(ssl_read_ex_prog, g_bpf_ssl_binary, g_bpf_ssl_read_ex_offset, "SSL_read_ex", true);
    } else {
        printf("[BPF] WARNING: SSL_read_ex return probe not found in BPF object\n");
    }

    const char *ssl_write_ex_entry_names[] = {"SSL_write_ex_entry", "uprobe/SSL_write_ex", "SSL_write_ex_uprobe", "SSL_write_ex"};
    struct bpf_program *ssl_write_ex_entry_prog = find_bpf_program(obj, ssl_write_ex_entry_names, sizeof(ssl_write_ex_entry_names) / sizeof(ssl_write_ex_entry_names[0]));
    if (ssl_write_ex_entry_prog) {
        g_bpf_ssl_write_ex_entry_link = attach_uprobe_prog_by_program(ssl_write_ex_entry_prog, g_bpf_ssl_binary, g_bpf_ssl_write_ex_offset, "SSL_write_ex entry", false);
    } else {
        printf("[BPF] WARNING: SSL_write_ex entry probe not found in BPF object\n");
    }

    const char *ssl_write_ex_names[] = {"SSL_write_ex_retprobe", "uretprobe/SSL_write_ex", "SSL_write_ex_ret"};
    struct bpf_program *ssl_write_ex_prog = find_bpf_program(obj, ssl_write_ex_names, sizeof(ssl_write_ex_names) / sizeof(ssl_write_ex_names[0]));
    if (ssl_write_ex_prog) {
        g_bpf_ssl_write_ex_link = attach_uprobe_prog_by_program(ssl_write_ex_prog, g_bpf_ssl_binary, g_bpf_ssl_write_ex_offset, "SSL_write_ex", true);
    } else {
        printf("[BPF] WARNING: SSL_write_ex return probe not found in BPF object\n");
    }

    if (g_bpf_ssl_read_ex_entry_link && g_bpf_ssl_read_ex_link) atomic_store(&g_bpf_ssl_read_ex_attached, true);
    if (g_bpf_ssl_write_ex_entry_link && g_bpf_ssl_write_ex_link) atomic_store(&g_bpf_ssl_write_ex_attached, true);

    int attached_probes = 0;
    attached_probes += g_bpf_ssl_read_entry_link ? 1 : 0;
    attached_probes += g_bpf_ssl_read_link ? 1 : 0;
    attached_probes += g_bpf_ssl_write_entry_link ? 1 : 0;
    attached_probes += g_bpf_ssl_write_link ? 1 : 0;
    attached_probes += g_bpf_ssl_read_ex_link ? 1 : 0;
    attached_probes += g_bpf_ssl_write_ex_link ? 1 : 0;

    bool any_ssl = atomic_load(&g_bpf_ssl_read_attached) || atomic_load(&g_bpf_ssl_write_attached) ||
                   atomic_load(&g_bpf_ssl_read_ex_attached) || atomic_load(&g_bpf_ssl_write_ex_attached);
    char summary[256];
    if (any_ssl) {
        snprintf(summary, sizeof(summary), "[BPF] attached %d probes; SSL handshake tracing enabled: read=%s write=%s read_ex=%s write_ex=%s",
                 attached_probes,
                 atomic_load(&g_bpf_ssl_read_attached) ? "OK" : "NO",
                 atomic_load(&g_bpf_ssl_write_attached) ? "OK" : "NO",
                 atomic_load(&g_bpf_ssl_read_ex_attached) ? "OK" : "NO",
                 atomic_load(&g_bpf_ssl_write_ex_attached) ? "OK" : "NO");
    } else {
        snprintf(summary, sizeof(summary), "[BPF] attached %d probes; SSL handshake tracing not attached", attached_probes);
    }
    printf("[BPF] attached %d SSL probe%s\n", attached_probes, attached_probes == 1 ? "" : "s");
    pthread_mutex_lock(&g_tui.log_mutex);
    snprintf(g_tui.startup_message, sizeof(g_tui.startup_message), "%s", summary);
    for (size_t i = 0; i < TUI_LINES; ++i) g_tui.log_buffer[i][0] = '\0';
    g_tui.last_event[0] = '\0';
    atomic_store(&g_tui.log_idx, 0);
    pthread_mutex_unlock(&g_tui.log_mutex);
}
static int ringbuf_event_handler(void *ctx, void *data, size_t size);
static void *ringbuf_worker(void *arg);
static void *pec_worker(void *arg);
static void *tui_worker(void *arg);

/* ============================================================================
   UTILS
============================================================================ */
static inline uint64_t get_time_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC_RAW, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static uint64_t bpf_stats_read(uint32_t index) {
    uint64_t value = 0;
    if (g_bpf_stats_fd >= 0) {
        if (bpf_map_lookup_elem(g_bpf_stats_fd, &index, &value) < 0) return 0;
    }
    return value;
}

static int ringbuf_open_pinned(const char *pin_path) {
    int fd = bpf_obj_get(pin_path);
    if (fd >= 0) {
        printf("[BPF] Opened pinned ringbuf map %s\n", pin_path);
    }
    return fd;
}

static void log_bpf_privileges(void) {
    char logline[256];
    struct rlimit cur_rlim;
    getrlimit(RLIMIT_MEMLOCK, &cur_rlim);
    int uid = getuid();
    int euid = geteuid();
    int sup_bpf = prctl(PR_CAPBSET_READ, CAP_BPF);
    int sup_admin = prctl(PR_CAPBSET_READ, CAP_SYS_ADMIN);
    snprintf(logline, sizeof(logline), "[BPF] uid=%d euid=%d cap_bpf=%d cap_sys_admin=%d RLIMIT_MEMLOCK=%lld/%lld",
             uid, euid, sup_bpf, sup_admin,
             (long long)cur_rlim.rlim_cur, (long long)cur_rlim.rlim_max);
    push_log(logline);
}

static bool resolve_bpf_object_path(char *dst, size_t size, const char *path) {
    if (!dst || size == 0 || !path || !*path) return false;

    char abs_path[PATH_MAX];
    if (access(path, R_OK) == 0) {
        if (realpath(path, abs_path)) {
            strncpy(dst, abs_path, size - 1);
            dst[size - 1] = '\0';
            return true;
        }
        strncpy(dst, path, size - 1);
        dst[size - 1] = '\0';
        return true;
    }

    char exe_path[PATH_MAX];
    ssize_t len = readlink("/proc/self/exe", exe_path, sizeof(exe_path) - 1);
    if (len <= 0) return false;
    exe_path[len] = '\0';

    char *exe_dir = strrchr(exe_path, '/');
    if (!exe_dir) return false;
    *exe_dir = '\0';

    char candidate[PATH_MAX];
    snprintf(candidate, sizeof(candidate), "%s/%s", exe_path, path);
    if (access(candidate, R_OK) == 0) {
        if (realpath(candidate, abs_path)) {
            strncpy(dst, abs_path, size - 1);
            dst[size - 1] = '\0';
            return true;
        }
        strncpy(dst, candidate, size - 1);
        dst[size - 1] = '\0';
        return true;
    }

    snprintf(candidate, sizeof(candidate), "%s/../%s", exe_path, path);
    if (access(candidate, R_OK) == 0) {
        if (realpath(candidate, abs_path)) {
            strncpy(dst, abs_path, size - 1);
            dst[size - 1] = '\0';
            return true;
        }
        strncpy(dst, candidate, size - 1);
        dst[size - 1] = '\0';
        return true;
    }

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;
    snprintf(candidate, sizeof(candidate), "%s/ebpf/%s", exe_path, base);
    if (access(candidate, R_OK) == 0) {
        if (realpath(candidate, abs_path)) {
            strncpy(dst, abs_path, size - 1);
            dst[size - 1] = '\0';
            return true;
        }
        strncpy(dst, candidate, size - 1);
        dst[size - 1] = '\0';
        return true;
    }

    snprintf(candidate, sizeof(candidate), "%s/../ebpf/%s", exe_path, base);
    if (access(candidate, R_OK) == 0) {
        if (realpath(candidate, abs_path)) {
            strncpy(dst, abs_path, size - 1);
            dst[size - 1] = '\0';
            return true;
        }
        strncpy(dst, candidate, size - 1);
        dst[size - 1] = '\0';
        return true;
    }

    return false;
}

static inline int select_sq_cpu(void) {
    int cur = sched_getcpu();
    int total = sysconf(_SC_NPROCESSORS_ONLN);
    return (total > 1) ? ((cur + 1) % total) : 0;
}

static uint32_t env_u32(const char *name, uint32_t def) {
    const char *value = getenv(name);
    if (!value || !*value) return def;
    char *end = NULL;
    unsigned long v = strtoul(value, &end, 0);
    return (end && *end == '\0') ? (uint32_t)v : def;
}

static float env_f32(const char *name, float def) {
    const char *value = getenv(name);
    if (!value || !*value) return def;
    char *end = NULL;
    float v = strtof(value, &end);
    return (end && *end == '\0') ? v : def;
}

static bool env_bool(const char *name, bool def) {
    const char *value = getenv(name);
    if (!value || !*value) return def;
    if (strcasecmp(value, "0") == 0 || strcasecmp(value, "false") == 0 || strcasecmp(value, "no") == 0) return false;
    return true;
}

static bool path_accessible(const char *path) {
    return path && *path && access(path, R_OK) == 0;
}

static const char *resolve_ssl_library_path(const char *requested) {
    static const char *candidates[] = {
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/aarch64-linux-gnu/libssl.so",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so",
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/usr/lib/x86_64-linux-gnu/libssl.so",
        "/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so",
        "/usr/lib/libssl.so.3",
        "/usr/lib/libssl.so",
        "/lib/libssl.so.3",
        "/lib/libssl.so",
    };

    if (requested && *requested && path_accessible(requested)) {
        return requested;
    }

    for (size_t i = 0; i < sizeof(candidates) / sizeof(candidates[0]); ++i) {
        if (path_accessible(candidates[i])) {
            return candidates[i];
        }
    }
    return requested;
}

static const char *detect_default_bpf_iface(const char *remote_host) {
    static char detected_iface[IF_NAMESIZE] = {0};
    detected_iface[0] = '\0';

    struct sockaddr_in remote = {0};
    struct sockaddr_in local = {0};
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return NULL;

    if (remote_host && *remote_host && strcmp(remote_host, "127.0.0.1") != 0 && strcmp(remote_host, "localhost") != 0) {
        struct addrinfo hints = {0};
        struct addrinfo *res = NULL;
        hints.ai_family = AF_INET;
        hints.ai_socktype = SOCK_DGRAM;
        if (getaddrinfo(remote_host, "53", &hints, &res) == 0 && res) {
            if (res->ai_addrlen == sizeof(remote)) {
                memcpy(&remote, res->ai_addr, sizeof(remote));
            }
            freeaddrinfo(res);
        }
    }
    if (remote.sin_addr.s_addr == 0) {
        remote.sin_family = AF_INET;
        remote.sin_port = htons(53);
        inet_pton(AF_INET, "1.1.1.1", &remote.sin_addr);
    }

    remote.sin_family = AF_INET;
    remote.sin_port = htons(53);
    if (connect(sock, (struct sockaddr *)&remote, sizeof(remote)) == 0) {
        socklen_t len = sizeof(local);
        if (getsockname(sock, (struct sockaddr *)&local, &len) == 0) {
            struct ifaddrs *ifap = NULL;
            if (getifaddrs(&ifap) == 0 && ifap) {
                for (struct ifaddrs *ifa = ifap; ifa; ifa = ifa->ifa_next) {
                    if (!ifa->ifa_addr || ifa->ifa_addr->sa_family != AF_INET) continue;
                    struct sockaddr_in *addr = (struct sockaddr_in *)ifa->ifa_addr;
                    if (addr->sin_addr.s_addr != local.sin_addr.s_addr) continue;
                    if (!(ifa->ifa_flags & IFF_LOOPBACK)) {
                        strncpy(detected_iface, ifa->ifa_name, sizeof(detected_iface) - 1);
                        detected_iface[sizeof(detected_iface) - 1] = '\0';
                        break;
                    }
                    if (detected_iface[0] == '\0') {
                        strncpy(detected_iface, ifa->ifa_name, sizeof(detected_iface) - 1);
                        detected_iface[sizeof(detected_iface) - 1] = '\0';
                    }
                }
                freeifaddrs(ifap);
            }
        }
    }
    close(sock);
    return detected_iface[0] ? detected_iface : NULL;
}

static const char *find_ssl_binary_path(void) {
    const char *candidates[] = {
#ifdef __aarch64__
        "/usr/lib/aarch64-linux-gnu/libssl.so.3",
        "/lib/aarch64-linux-gnu/libssl.so.3",
        "/usr/lib/arm-linux-gnueabihf/libssl.so.3",
        "/lib/arm-linux-gnueabihf/libssl.so.3",
#endif
#ifdef __x86_64__
        "/usr/lib/x86_64-linux-gnu/libssl.so.3",
        "/lib/x86_64-linux-gnu/libssl.so.3",
#endif
        "/usr/lib/libssl.so.3",
        "/lib/libssl.so.3",
        NULL,
    };

    const char *paths[] = {
        getenv("NEXUS_SSL_LIB_PATH"),
        getenv("PEC_SSL_LIB_PATH"),
        getenv("NEXUS_BPF_SSL_BINARY"),
        getenv("PEC_BPF_SSL_BINARY"),
        NULL,
    };

    for (const char **p = paths; p && *p; p++) {
        if (path_accessible(*p)) return *p;
    }

    for (const char **c = candidates; c && *c; c++) {
        if (path_accessible(*c)) return *c;
    }
    return NULL;
}

static void configure_defaults(void) {
    g_worker_threads = env_u32("NEXUS_MAX_THREADS", DEFAULT_PEC_WORKER_THREADS);
    if (g_worker_threads == 0) g_worker_threads = DEFAULT_PEC_WORKER_THREADS;

    float magic_interval = env_f32("NEXUS_EBPF_MAGIC_INTERVAL_SEC", 0.25f);
    g_tui_update_ms = (uint32_t)(magic_interval * 1000.0f);
    if (g_tui_update_ms < 50) g_tui_update_ms = DEFAULT_UI_UPDATE_MS;

    g_ringbuf_poll_ms = env_u32("NEXUS_METASOCKET_BACKPRESSURE_THRESHOLD_MS", DEFAULT_RINGBUF_POLL_MS);
    if (g_ringbuf_poll_ms < 10) g_ringbuf_poll_ms = DEFAULT_RINGBUF_POLL_MS;

    const char *env_iface = getenv("NEXUS_BPF_IFACE");
    if (env_iface && *env_iface) {
        g_bpf_iface = env_iface;
    } else {
        const char *detected_iface = detect_default_bpf_iface(g_target.host);
        if (detected_iface) {
            g_bpf_iface = detected_iface;
            char logline[256];
            snprintf(logline, sizeof(logline), "[BPF] Auto-detected default interface: %s", g_bpf_iface);
            push_log(logline);
        } else {
            g_bpf_iface = "";
            push_log("[BPF] No BPF interface configured; capturing on all interfaces");
        }
    }
    const char *env_mode = getenv("NEXUS_BPF_MODE");
    if (env_mode && *env_mode) {
        if (is_valid_bpf_mode(env_mode)) g_bpf_mode = env_mode;
        else fprintf(stderr, "[WARN] Invalid NEXUS_BPF_MODE '%s'; using %s\n", env_mode, g_bpf_mode);
    }

    const char *env_ssl_bin = getenv("NEXUS_SSL_LIB_PATH");
    if (!env_ssl_bin || !*env_ssl_bin) env_ssl_bin = getenv("PEC_SSL_LIB_PATH");
    if (!env_ssl_bin || !*env_ssl_bin) env_ssl_bin = getenv("NEXUS_BPF_SSL_BINARY");
    if (!env_ssl_bin || !*env_ssl_bin) env_ssl_bin = getenv("PEC_BPF_SSL_BINARY");
    if (path_accessible(env_ssl_bin)) {
        g_bpf_ssl_binary = env_ssl_bin;
    } else {
        const char *fallback_ssl = find_ssl_binary_path();
        if (fallback_ssl) g_bpf_ssl_binary = fallback_ssl;
    }

    if (path_accessible(g_bpf_ssl_binary)) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] SSL uprobe binary resolved to %s", g_bpf_ssl_binary);
        push_log(logline);
    } else {
        char logline[256];
        snprintf(logline, sizeof(logline), "[WARN] SSL uprobe binary not accessible: %s", g_bpf_ssl_binary);
        fprintf(stderr, "%s\n", logline);
        push_log(logline);
    }

    if (getenv("NEXUS_BPF_SSL_READ_OFFSET")) {
        g_bpf_ssl_read_offset = env_size("NEXUS_BPF_SSL_READ_OFFSET", g_bpf_ssl_read_offset);
    } else if (getenv("PEC_BPF_SSL_READ_OFFSET")) {
        g_bpf_ssl_read_offset = env_size("PEC_BPF_SSL_READ_OFFSET", g_bpf_ssl_read_offset);
    }
    if (getenv("NEXUS_BPF_SSL_READ_EX_OFFSET")) {
        g_bpf_ssl_read_ex_offset = env_size("NEXUS_BPF_SSL_READ_EX_OFFSET", g_bpf_ssl_read_ex_offset);
    } else if (getenv("PEC_BPF_SSL_READ_EX_OFFSET")) {
        g_bpf_ssl_read_ex_offset = env_size("PEC_BPF_SSL_READ_EX_OFFSET", g_bpf_ssl_read_ex_offset);
    }

    if (getenv("NEXUS_BPF_SSL_WRITE_OFFSET")) {
        g_bpf_ssl_write_offset = env_size("NEXUS_BPF_SSL_WRITE_OFFSET", g_bpf_ssl_write_offset);
    } else if (getenv("PEC_BPF_SSL_WRITE_OFFSET")) {
        g_bpf_ssl_write_offset = env_size("PEC_BPF_SSL_WRITE_OFFSET", g_bpf_ssl_write_offset);
    }
    if (getenv("NEXUS_BPF_SSL_WRITE_EX_OFFSET")) {
        g_bpf_ssl_write_ex_offset = env_size("NEXUS_BPF_SSL_WRITE_EX_OFFSET", g_bpf_ssl_write_ex_offset);
    } else if (getenv("PEC_BPF_SSL_WRITE_EX_OFFSET")) {
        g_bpf_ssl_write_ex_offset = env_size("PEC_BPF_SSL_WRITE_EX_OFFSET", g_bpf_ssl_write_ex_offset);
    }

    g_bpf_god_mode = env_bool("NEXUS_BPF_GOD_MODE", g_bpf_god_mode) || env_bool("PEC_BPF_GOD_MODE", g_bpf_god_mode);
    atomic_store(&g_sniper_bot_enabled, env_bool("NEXUS_SNIPER_BOT", atomic_load(&g_sniper_bot_enabled)));
    atomic_store(&g_anti_rug_enabled, env_bool("NEXUS_ANTI_RUG", atomic_load(&g_anti_rug_enabled)));
    atomic_store(&g_mev_protection_enabled, env_bool("NEXUS_MEV_PROTECTION", atomic_load(&g_mev_protection_enabled)));
    atomic_store(&g_copy_trading_enabled, env_bool("NEXUS_COPY_TRADING", atomic_load(&g_copy_trading_enabled)));
    atomic_store(&g_auto_snipe_enabled, env_bool("NEXUS_AUTO_SNIPE", atomic_load(&g_auto_snipe_enabled)));

    const char *contract_arg = getenv("NEXUS_BPF_TARGET_CONTRACT");
    if (!contract_arg || !*contract_arg) contract_arg = getenv("PEC_BPF_TARGET_CONTRACT");
    parse_pattern_arg(contract_arg, (uint8_t *)g_bot_target_contract, &g_bot_target_contract_len, sizeof(g_bot_target_contract));
    const char *event_sig_arg = getenv("NEXUS_BPF_EVENT_SIGNATURE");
    if (!event_sig_arg || !*event_sig_arg) event_sig_arg = getenv("PEC_BPF_EVENT_SIGNATURE");
    parse_pattern_arg(event_sig_arg, (uint8_t *)g_bot_event_signature, &g_bot_event_signature_len, sizeof(g_bot_event_signature));

    const char *api_key = getenv("NEXUS_API_KEY");
    if (api_key && *api_key) strncpy(g_bot_api_key, api_key, sizeof(g_bot_api_key) - 1);
    const char *api_secret = getenv("NEXUS_API_SECRET");
    if (api_secret && *api_secret) strncpy(g_bot_api_secret, api_secret, sizeof(g_bot_api_secret) - 1);
    const char *wallet = getenv("NEXUS_COPY_WALLET");
    if (wallet && *wallet) strncpy(g_copy_wallet, wallet, sizeof(g_copy_wallet) - 1);

    g_bybit_max_price_usdt = env_f32("NEXUS_BYBIT_MAX_PRICE", g_bybit_max_price_usdt);
    const char *max_allowed_price = getenv("MAX_ALLOWED_PRICE_USDT");
    if (max_allowed_price && *max_allowed_price) {
        g_bybit_max_price_usdt = (float)atof(max_allowed_price);
    }
    g_bybit_min_liquidity = env_f32("NEXUS_BYBIT_MIN_LIQUIDITY", g_bybit_min_liquidity);
    g_bybit_min_whale_wall_usdt = env_f32("NEXUS_BYBIT_MIN_WHALE_WALL_USDT", g_bybit_min_whale_wall_usdt);
    g_bybit_score_threshold = env_f32("NEXUS_BYBIT_SCORE_THRESHOLD", g_bybit_score_threshold);
    g_bybit_price_delta_pct = env_f32("NEXUS_BYBIT_DELTA_PCT", g_bybit_price_delta_pct);
    g_bybit_imbalance_ratio = env_f32("NEXUS_BYBIT_IMBALANCE_RATIO", g_bybit_imbalance_ratio);
    g_bybit_exit_imbalance_ratio = env_f32("NEXUS_BYBIT_EXIT_IMBALANCE_RATIO", g_bybit_exit_imbalance_ratio);
    g_bybit_internal_latency_spike_ms = env_f32("NEXUS_BYBIT_INTERNAL_LATENCY_SPIKE_MS", g_bybit_internal_latency_spike_ms);
    g_bybit_latency_tolerance_ms = env_f32("NEXUS_BYBIT_LATENCY_MS", g_bybit_latency_tolerance_ms);
    g_bot_slippage_pct = env_f32("NEXUS_BOT_SLIPPAGE_PCT", g_bot_slippage_pct);
    g_bot_take_profit_pct = env_f32("NEXUS_BOT_TP_PCT", g_bot_take_profit_pct);
    g_bot_stop_loss_pct = env_f32("NEXUS_BOT_SL_PCT", g_bot_stop_loss_pct);
    g_bot_trade_cooldown_ns = (uint64_t)env_u32("NEXUS_BOT_COOLDOWN_SEC", DEFAULT_BOT_COOLDOWN_SEC) * 1000000000ULL;
    float sniper_env_qty = env_f32("SNIPER_TRADE_USDT", env_f32("NEXUS_SNIPER_TRADE_USDT", 0.0f));
    if (sniper_env_qty > 0.0f) {
        g_sniper_trade_usdt = sniper_env_qty;
        g_bot_trade_cooldown_ns = SNIPER_TRADE_COOLDOWN_MS * 1000000ULL;
    }
    atomic_store(&g_bot_direct_splice, env_bool("NEXUS_BOT_DIRECT_SPLICE", false) || env_bool("PEC_BOT_DIRECT_SPLICE", false));
    atomic_store(&g_bot_wormhole, env_bool("NEXUS_BOT_WORMHOLE", false) || env_bool("PEC_BOT_WORMHOLE", false));
    atomic_store(&g_bot_x11_stealth, env_bool("NEXUS_BOT_X11_STEALTH", false) || env_bool("PEC_BOT_X11_STEALTH", false));
    atomic_store(&g_bybit_keepalive, env_bool("NEXUS_BYBIT_KEEPALIVE", true));
    atomic_store(&g_amx_warmup_enabled, env_bool("NEXUS_AMX_WARMUP", atomic_load(&g_amx_warmup_enabled)));
    const char *presigned_tx = getenv("NEXUS_BYBIT_PRESIGNED_TX");
    if (presigned_tx && *presigned_tx) strncpy(g_bybit_presigned_tx, presigned_tx, sizeof(g_bybit_presigned_tx) - 1);

    if (atomic_load(&g_auto_snipe_enabled) || atomic_load(&g_copy_trading_enabled) || atomic_load(&g_anti_rug_enabled) || atomic_load(&g_mev_protection_enabled)) {
        atomic_store(&g_sniper_bot_enabled, true);
    }

    if (atomic_load(&g_sniper_bot_enabled) && g_ringbuf_poll_ms > 10) {
        g_ringbuf_poll_ms = 10;
    }

    g_pec_sleep_min_ms = env_u32("NEXUS_SMUGGLE_CONTINUOUS_SLEEP_MIN", DEFAULT_PEC_SLEEP_MIN_MS);
    g_pec_sleep_max_ms = env_u32("NEXUS_SMUGGLE_CONTINUOUS_SLEEP_MAX", DEFAULT_PEC_SLEEP_MAX_MS);
    if (g_pec_sleep_min_ms == 0) g_pec_sleep_min_ms = DEFAULT_PEC_SLEEP_MIN_MS;
    if (g_pec_sleep_max_ms < g_pec_sleep_min_ms) g_pec_sleep_max_ms = g_pec_sleep_min_ms;
    g_raw_stream_log = env_bool("NEXUS_RAW_STREAM_LOG", true);
}

struct bpf_filter_config {
    uint32_t contract_len;
    uint32_t event_sig_len;
    uint32_t price_delta_bps;
    uint8_t contract[32];
    uint8_t event_sig[32];
    uint8_t reserved[20];
};

static int hex_digit(char c) {
    if (c >= '0' && c <= '9') return c - '0';
    if (c >= 'a' && c <= 'f') return c - 'a' + 10;
    if (c >= 'A' && c <= 'F') return c - 'A' + 10;
    return -1;
}

static size_t parse_hex_pattern(const char *input, uint8_t *output, size_t max_len) {
    if (!input || !*input || !output || max_len == 0) return 0;
    if (input[0] != '0' || (input[1] != 'x' && input[1] != 'X')) return 0;
    const char *hex = input + 2;
    size_t len = strlen(hex);
    if (len % 2 != 0) return 0;
    size_t count = len / 2;
    if (count > max_len) return 0;
    for (size_t i = 0; i < count; i++) {
        int hi = hex_digit(hex[i * 2]);
        int lo = hex_digit(hex[i * 2 + 1]);
        if (hi < 0 || lo < 0) return 0;
        output[i] = (uint8_t)((hi << 4) | lo);
    }
    return count;
}

static void parse_pattern_arg(const char *input, uint8_t *output, size_t *out_len, size_t max_len) {
    if (!input || !*input || !output || !out_len || max_len == 0) {
        if (out_len) *out_len = 0;
        return;
    }
    size_t len = parse_hex_pattern(input, output, max_len);
    if (len > 0) {
        *out_len = len;
        return;
    }
    len = strnlen(input, max_len);
    memcpy(output, input, len);
    *out_len = len;
}

static void apply_bpf_filter_config(struct bpf_object *obj) {
    if (!obj) return;
    int map_fd = bpf_object__find_map_fd_by_name(obj, "filter_config");
    if (map_fd < 0) return;
    struct bpf_filter_config cfg = {0};
    cfg.contract_len = g_bot_target_contract_len > sizeof(cfg.contract) ? sizeof(cfg.contract) : g_bot_target_contract_len;
    if (cfg.contract_len) memcpy(cfg.contract, g_bot_target_contract, cfg.contract_len);
    cfg.event_sig_len = g_bot_event_signature_len > sizeof(cfg.event_sig) ? sizeof(cfg.event_sig) : g_bot_event_signature_len;
    if (cfg.event_sig_len) memcpy(cfg.event_sig, g_bot_event_signature, cfg.event_sig_len);
    cfg.price_delta_bps = g_bybit_price_delta_pct > 0.0f ? (uint32_t)(g_bybit_price_delta_pct * 100.0f + 0.5f) : 0;
    __u32 key = 0;
    if (bpf_map_update_elem(map_fd, &key, &cfg, BPF_ANY) != 0) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[BPF] Failed to update filter_config map: %s", strerror(errno));
        fprintf(stderr, "%s\n", logline);
        push_log(logline);
    } else if (cfg.contract_len || cfg.event_sig_len) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[BPF] Loaded filter config: %u contract / %u event", cfg.contract_len, cfg.event_sig_len);
        push_log(logline);
    }
}

static bool payload_contains(const uint8_t *data, size_t data_len, const uint8_t *pattern, size_t pat_len) {
    if (!data || !pattern || pat_len == 0 || data_len < pat_len) return false;
    for (size_t i = 0; i <= data_len - pat_len; i++) {
        if (memcmp(data + i, pattern, pat_len) == 0) return true;
    }
    return false;
}

static bool payload_contains_ci(const uint8_t *data, size_t data_len, const uint8_t *pattern, size_t pat_len) {
    if (!data || !pattern || pat_len == 0 || data_len < pat_len) return false;
    for (size_t i = 0; i <= data_len - pat_len; i++) {
        size_t j;
        for (j = 0; j < pat_len; j++) {
            uint8_t a = data[i + j];
            uint8_t b = pattern[j];
            if (a >= 'A' && a <= 'Z') a += 'a' - 'A';
            if (b >= 'A' && b <= 'Z') b += 'a' - 'A';
            if (a != b) break;
        }
        if (j == pat_len) return true;
    }
    return false;
}

static bool bot_contains_bybit_keyword(const struct matrix_event *evt) {
    if (!evt || evt->payload_len < 10) return false;

    if (payload_contains_ci(evt->data, evt->payload_len, (uint8_t *)"\"topic\":\"orderbook.", 20)) {
        if (payload_contains_ci(evt->data, evt->payload_len, (uint8_t *)"\"b\":", 4) ||
            payload_contains_ci(evt->data, evt->payload_len, (uint8_t *)"\"a\":", 4)) {
            return true;
        }
    }

    if (payload_contains_ci(evt->data, evt->payload_len, (uint8_t *)"\"success\":", 10)) {
        return true;
    }

    return false;
}

static const uint8_t *skip_json_number_prefix(const uint8_t *p, const uint8_t *end) {
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':' || *p == ',')) {
        p++;
    }
    if (p < end && *p == '"') {
        p++;
    }
    while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) {
        p++;
    }
    return p;
}

static bool parse_json_number_token(const uint8_t *start, const uint8_t *end, double *out) {
    if (!start || !end || !out || start >= end) return false;
    const uint8_t *p = skip_json_number_prefix(start, end);
    bool neg = false;
    if (p < end && (*p == '+' || *p == '-')) {
        neg = (*p == '-');
        p++;
    }
    double value = 0.0;
    bool has_digits = false;
    while (p < end && *p >= '0' && *p <= '9') {
        has_digits = true;
        value = value * 10.0 + (double)(*p - '0');
        p++;
    }
    if (p < end && *p == '.') {
        p++;
        double frac = 0.0;
        double scale = 1.0;
        while (p < end && *p >= '0' && *p <= '9') {
            frac = frac * 10.0 + (double)(*p - '0');
            scale *= 10.0;
            p++;
        }
        value += frac / scale;
    }
    if (!has_digits) return false;
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        bool exp_neg = false;
        if (p < end && (*p == '+' || *p == '-')) {
            exp_neg = (*p == '-');
            p++;
        }
        int exp = 0;
        if (p >= end || *p < '0' || *p > '9') return false;
        while (p < end && *p >= '0' && *p <= '9') {
            exp = exp * 10 + (*p - '0');
            p++;
        }
        double power = 1.0;
        while (exp-- > 0) power *= 10.0;
        value = exp_neg ? value / power : value * power;
    }
    if (neg) value = -value;
    *out = value;
    return true;
}

static bool parse_json_uint64_token(const uint8_t *start, const uint8_t *end, uint64_t *out) {
    if (!start || !end || !out || start >= end) return false;
    const uint8_t *p = skip_json_number_prefix(start, end);
    if (p < end && (*p == '+' || *p == '-')) {
        if (*p == '-') return false;
        p++;
    }
    uint64_t value = 0;
    bool has_digits = false;
    while (p < end && *p >= '0' && *p <= '9') {
        has_digits = true;
        uint64_t digit = (uint64_t)(*p - '0');
        if (value > (UINT64_MAX - digit) / 10ULL) return false;
        value = value * 10ULL + digit;
        p++;
    }
    if (!has_digits) return false;
    *out = value;
    return true;
}

static const uint8_t *parse_json_number_token_end(const uint8_t *start, const uint8_t *end, double *out) {
    if (!parse_json_number_token(start, end, out)) return NULL;
    const uint8_t *p = skip_json_number_prefix(start, end);
    if (p < end && (*p == '+' || *p == '-')) p++;
    while (p < end && (*p >= '0' && *p <= '9')) p++;
    if (p < end && *p == '.') {
        p++;
        while (p < end && (*p >= '0' && *p <= '9')) p++;
    }
    if (p < end && (*p == 'e' || *p == 'E')) {
        p++;
        if (p < end && (*p == '+' || *p == '-')) p++;
        while (p < end && (*p >= '0' && *p <= '9')) p++;
    }
    if (p < end && *p == '"') p++;
    return p;
}

static bool bot_extract_bybit_ws_price_qty(const uint8_t *data, size_t data_len, const char *key, double *price, double *qty) {
    if (!data || !key || !price || !qty) return false;
    size_t key_len = strlen(key);
    const uint8_t *end = data + data_len;
    const uint8_t *p = memmem(data, data_len, key, key_len);
    if (!p) return false;
    p += key_len;

    while (p < end && *p != '"' && *p != '\'' && *p != '[' && *p != '-' && *p != '+' && (*p < '0' || *p > '9')) p++;
    if (p < end && (*p == '"' || *p == '\'')) p++;
    const uint8_t *price_start = p;
    if (!parse_json_number_token(price_start, end, price)) return false;
    const uint8_t *q = price_start;
    while (q < end && ((*q >= '0' && *q <= '9') || *q == '+' || *q == '-' || *q == '.' || *q == 'e' || *q == 'E')) q++;
    if (q < end && *q == '"') q++;
    while (q < end && *q != '"' && *q != '\'' && q < end) q++;
    if (q < end && (*q == '"' || *q == '\'')) q++;
    const uint8_t *qty_start = q;
    while (qty_start < end && *qty_start != '"' && *qty_start != '\'' && (*qty_start < '0' || *qty_start > '9') && *qty_start != '-' && *qty_start != '+') qty_start++;
    if (qty_start < end && (*qty_start == '"' || *qty_start == '\'')) qty_start++;
    if (!parse_json_number_token(qty_start, end, qty)) return false;
    return true;
}

static bool bot_extract_json_number(const uint8_t *data, size_t data_len, const char *key, double *out) {
    if (!data || !key || !out) return false;
    size_t key_len = strlen(key);
    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        size_t j = i + key_len;
        const uint8_t *start = skip_json_number_prefix(data + j, data + data_len);
        const uint8_t *end = data + data_len;
        if (parse_json_number_token(start, end, out)) return true;
    }
    return false;
}

static bool bot_extract_json_uint64(const uint8_t *data, size_t data_len, const char *key, uint64_t *out) {
    if (!data || !key || !out) return false;
    size_t key_len = strlen(key);
    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        size_t j = i + key_len;
        const uint8_t *start = skip_json_number_prefix(data + j, data + data_len);
        if (parse_json_uint64_token(start, data + data_len, out)) return true;
    }
    return false;
}

static bool bot_extract_json_timestamp(const uint8_t *data, size_t data_len, uint64_t *timestamp_out) {
    if (!data || !timestamp_out) return false;
    if (bot_extract_json_uint64(data, data_len, "\"timestamp\"", timestamp_out)) return true;
    if (bot_extract_json_uint64(data, data_len, "\"ts\"", timestamp_out)) return true;
    if (bot_extract_json_uint64(data, data_len, "\"time\"", timestamp_out)) return true;
    return false;
}

static bool bot_extract_json_string(const uint8_t *data, size_t data_len, const char *key, char *out, size_t out_size) {
    if (!data || !key || !out || out_size == 0) return false;
    size_t key_len = strlen(key);
    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        const uint8_t *p = data + i + key_len;
        while (p < data + data_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':')) p++;
        if (p >= data + data_len || *p != '"') continue;
        p++;
        size_t j = 0;
        while (p < data + data_len && *p != '"' && j + 1 < out_size) {
            out[j++] = *p++;
        }
        out[j] = '\0';
        return true;
    }
    return false;
}

static bool bot_extract_json_number_token_string(const uint8_t *data, size_t data_len, const char *key, char *out, size_t out_size) {
    if (!data || !key || !out || out_size == 0) return false;
    size_t key_len = strlen(key);
    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        const uint8_t *p = data + i + key_len;
        while (p < data + data_len && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':')) p++;
        if (p >= data + data_len) return false;

        if (*p == '"') {
            p++;
            size_t j = 0;
            while (p < data + data_len && *p != '"' && j + 1 < out_size) {
                out[j++] = *p++;
            }
            out[j] = '\0';
            return true;
        }

        const uint8_t *start = p;
        while (p < data + data_len && ((*p >= '0' && *p <= '9') || *p == '+' || *p == '-' || *p == '.' || *p == 'e' || *p == 'E')) {
            p++;
        }
        size_t len = p - start;
        if (len == 0 || len >= out_size) return false;
        memcpy(out, start, len);
        out[len] = '\0';
        return true;
    }
    return false;
}

static inline void atomic_store_float(_Atomic uint32_t *dst, float value) {
    uint32_t bits;
    memcpy(&bits, &value, sizeof(bits));
    atomic_store(dst, bits);
}

static inline float atomic_load_float(_Atomic uint32_t *src) {
    uint32_t bits = atomic_load(src);
    float value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static inline double atomic_load_float64(_Atomic uint64_t *src) {
    uint64_t bits = atomic_load(src);
    double value;
    memcpy(&value, &bits, sizeof(value));
    return value;
}

static inline void atomic_store_float64(_Atomic uint64_t *dst, double value) {
    uint64_t bits;
    memcpy(&bits, &value, sizeof(bits));
    atomic_store(dst, bits);
}

static bool bot_extract_json_array_pair(const uint8_t *data, size_t data_len, const char *key, double *first_out, double *second_out) {
    if (!data || !key || !first_out || !second_out) return false;
    size_t key_len = strlen(key);
    const uint8_t *end = data + data_len;

    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        const uint8_t *p = data + i + key_len;
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n' || *p == ':')) p++;
        if (p >= end || *p != '[') continue;
        p++;
        while (p < end && (*p == ' ' || *p == '\t' || *p == '\r' || *p == '\n')) p++;
        if (p >= end || *p != '[') continue;
        p++;
        p = skip_json_number_prefix(p, end);
        const uint8_t *first_start = p;
        const uint8_t *next = parse_json_number_token_end(first_start, end, first_out);
        if (!next) continue;
        p = skip_json_number_prefix(next, end);
        if (p < end && *p == ',') p = skip_json_number_prefix(p + 1, end);
        if (p >= end) continue;
        if (!parse_json_number_token(p, end, second_out)) continue;
        return true;
    }
    return false;
}

static bool bot_extract_orderbook_levels_from_object(const uint8_t *data, size_t data_len, double *bid_price, double *bid_qty, double *ask_price, double *ask_qty) {
    if (!data || data_len == 0 || !bid_price || !bid_qty || !ask_price || !ask_qty) return false;
    double bid_p = 0.0, bid_q = 0.0, ask_p = 0.0, ask_q = 0.0;
    bool got_bid = false;
    bool got_ask = false;

    if (bot_extract_json_number(data, data_len, "\"bid1Price\"", &bid_p) &&
        bot_extract_json_number(data, data_len, "\"bid1Qty\"", &bid_q)) {
        got_bid = true;
    }
    if (!got_bid && bot_extract_json_number(data, data_len, "\"bid1Price\"", &bid_p) &&
        bot_extract_json_number(data, data_len, "\"bid1Size\"", &bid_q)) {
        got_bid = true;
    }
    if (bot_extract_json_number(data, data_len, "\"ask1Price\"", &ask_p) &&
        bot_extract_json_number(data, data_len, "\"ask1Qty\"", &ask_q)) {
        got_ask = true;
    }
    if (!got_ask && bot_extract_json_number(data, data_len, "\"ask1Price\"", &ask_p) &&
        bot_extract_json_number(data, data_len, "\"ask1Size\"", &ask_q)) {
        got_ask = true;
    }

    if (got_bid) {
        *bid_price = bid_p;
        *bid_qty = bid_q;
    }
    if (got_ask) {
        *ask_price = ask_p;
        *ask_qty = ask_q;
    }
    return got_bid || got_ask;
}

static const uint8_t *bot_find_json_section(const uint8_t *data, size_t data_len, const char *key, size_t *section_len) {
    if (!data || !key || !section_len) return NULL;
    size_t key_len = strlen(key);
    const uint8_t *end = data + data_len;
    for (const uint8_t *p = data; p + key_len < end; p++) {
        if (memcmp(p, key, key_len) != 0) continue;
        const uint8_t *q = p + key_len;
        while (q < end && (*q == ' ' || *q == '\t' || *q == '\r' || *q == '\n' || *q == ':')) q++;
        if (q >= end) break;
        if (*q != '{' && *q != '[') continue;
        uint8_t open = *q;
        uint8_t close = (open == '{') ? '}' : ']';
        const uint8_t *start = q;
        q++;
        int depth = 1;
        while (q < end && depth > 0) {
            if (*q == open) depth++;
            else if (*q == close) depth--;
            q++;
        }
        if (depth == 0) {
            *section_len = (size_t)(q - start);
            return start;
        }
    }
    return NULL;
}

static bool bot_extract_json_symbol_from_data(const uint8_t *data, size_t data_len, char *symbol, size_t symbol_size);
static bool bot_symbols_equivalent(const char *a, const char *b);
static bool bot_is_solusdt_symbol(const char *symbol);

static bool bot_extract_orderbook_levels_in_section_with_symbol(const uint8_t *data, size_t data_len, int depth, const char *target_symbol, double *bid_price, double *bid_qty, double *ask_price, double *ask_qty) {
    if (!data || data_len == 0 || depth <= 0 || !bid_price || !bid_qty || !ask_price || !ask_qty) return false;
    double bid_p = 0.0, bid_q = 0.0, ask_p = 0.0, ask_q = 0.0;
    bool got_bid = false;
    bool got_ask = false;

    if (bot_extract_json_array_pair(data, data_len, "\"bids\"", &bid_p, &bid_q)) {
        got_bid = true;
    }
    if (bot_extract_json_array_pair(data, data_len, "\"asks\"", &ask_p, &ask_q)) {
        got_ask = true;
    }
    if (!got_bid && bot_extract_json_array_pair(data, data_len, "\"b\"", &bid_p, &bid_q)) {
        got_bid = true;
    }
    if (!got_ask && bot_extract_json_array_pair(data, data_len, "\"a\"", &ask_p, &ask_q)) {
        got_ask = true;
    }
    if (!got_bid && bot_extract_json_array_pair(data, data_len, "\"list\"", &bid_p, &bid_q)) {
        got_bid = true;
    }
    if (!got_ask) {
        if (bot_extract_json_array_pair(data, data_len, "\"a\"", &ask_p, &ask_q)) {
            got_ask = true;
        } else if (bot_extract_json_array_pair(data, data_len, "\"asks\"", &ask_p, &ask_q)) {
            got_ask = true;
        } else if (bot_extract_json_array_pair(data, data_len, "\"list\"", &ask_p, &ask_q)) {
            got_ask = true;
        }
    }
    if (got_bid || got_ask) {
        if (got_bid) {
            *bid_price = bid_p;
            *bid_qty = bid_q;
        }
        if (got_ask) {
            *ask_price = ask_p;
            *ask_qty = ask_q;
        }
        return true;
    }

    size_t section_len = 0;
    const uint8_t *section = bot_find_json_section(data, data_len, "\"data\"", &section_len);
    if (section && bot_extract_orderbook_levels_in_section_with_symbol(section, section_len, depth - 1, target_symbol, bid_price, bid_qty, ask_price, ask_qty)) {
        return true;
    }
    section = bot_find_json_section(data, data_len, "\"result\"", &section_len);
    if (section && bot_extract_orderbook_levels_in_section_with_symbol(section, section_len, depth - 1, target_symbol, bid_price, bid_qty, ask_price, ask_qty)) {
        return true;
    }

    return false;
}

static bool bot_extract_orderbook_levels_for_symbol(const uint8_t *data, size_t data_len, const char *symbol, double *bid_price, double *bid_qty, double *ask_price, double *ask_qty) {
    return bot_extract_orderbook_levels_in_section_with_symbol(data, data_len, 3, symbol, bid_price, bid_qty, ask_price, ask_qty);
}

static bool bot_extract_query_param(const uint8_t *data, size_t data_len, const char *key, char *out, size_t out_size) {
    if (!data || !key || !out || out_size == 0) return false;
    size_t key_len = strlen(key);
    for (size_t i = 0; i + key_len < data_len; i++) {
        if (memcmp(data + i, key, key_len) != 0) continue;
        const uint8_t *p = data + i + key_len;
        size_t j = 0;
        while (p < data + data_len && *p != '&' && *p != ' ' && *p != '\"' && *p != '\r' && *p != '\n' && j + 1 < out_size) {
            out[j++] = *p++;
        }
        if (j == 0) continue;
        out[j] = '\0';
        return true;
    }
    return false;
}

static bool bot_extract_json_symbol(const struct matrix_event *evt, char *symbol, size_t symbol_size) {
    if (!evt || !symbol || symbol_size == 0) return false;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"symbol\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"instId\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"instrument_id\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"contract\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"s\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(evt->data, evt->payload_len, "\"topic\"", symbol, symbol_size)) return true;
    if (bot_extract_query_param(evt->data, evt->payload_len, "symbol=", symbol, symbol_size)) return true;
    if (bot_extract_query_param(evt->data, evt->payload_len, "instId=", symbol, symbol_size)) return true;
    if (bot_extract_query_param(evt->data, evt->payload_len, "instrument_id=", symbol, symbol_size)) return true;
    return false;
}

static bool bot_symbols_equivalent(const char *a, const char *b) {
    if (!a || !b || !*a || !*b) return false;
    if (strcasecmp(a, b) == 0) return true;
    if (bot_is_solusdt_symbol(a) && bot_is_solusdt_symbol(b)) return true;
    return false;
}

static bool bot_extract_json_symbol_from_data(const uint8_t *data, size_t data_len, char *symbol, size_t symbol_size) {
    if (!data || !symbol || symbol_size == 0) return false;
    if (bot_extract_json_string(data, data_len, "\"symbol\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(data, data_len, "\"instId\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(data, data_len, "\"instrument_id\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(data, data_len, "\"contract\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(data, data_len, "\"s\"", symbol, symbol_size)) return true;
    if (bot_extract_json_string(data, data_len, "\"topic\"", symbol, symbol_size)) return true;
    if (bot_extract_query_param(data, data_len, "symbol=", symbol, symbol_size)) return true;
    if (bot_extract_query_param(data, data_len, "instId=", symbol, symbol_size)) return true;
    if (bot_extract_query_param(data, data_len, "instrument_id=", symbol, symbol_size)) return true;

    size_t section_len = 0;
    const uint8_t *section = bot_find_json_section(data, data_len, "\"result\"", &section_len);
    if (section && section_len > 0 && bot_extract_json_symbol_from_data(section, section_len, symbol, symbol_size)) return true;
    section = bot_find_json_section(data, data_len, "\"data\"", &section_len);
    if (section && section_len > 0 && bot_extract_json_symbol_from_data(section, section_len, symbol, symbol_size)) return true;
    section = bot_find_json_section(data, data_len, "\"list\"", &section_len);
    if (section && section_len > 0 && bot_extract_json_symbol_from_data(section, section_len, symbol, symbol_size)) return true;
    return false;
}

static bool bot_is_bybit_target(void) {
    if (strstr(g_target.target, "bybit.com") != NULL) return true;
    if (strstr(g_target.hostname, "bybit.com") != NULL) return true;
    if (strstr(g_target.host, "bybit.com") != NULL) return true;
    if (strstr(g_target.path, "/v5/public") != NULL || strstr(g_target.path, "/realtime") != NULL) return true;
    return false;
}

static void bot_normalize_bybit_path(target_config_t *cfg) {
    if (!cfg || !bot_is_bybit_target()) return;
    if (strstr(cfg->path, "category=") != NULL) return;

    const char *suffix = NULL;
    if (strstr(cfg->path, "symbol=SOLUSDT") || strstr(cfg->path, "symbol=SOL-USDT") || strstr(cfg->path, "symbol=SOL/USDT")) {
        suffix = strchr(cfg->path, '?') ? "&category=spot" : "?category=spot";
    }
    if (!suffix) return;
    strncat(cfg->path, suffix, sizeof(cfg->path) - strlen(cfg->path) - 1);
}

static bool bot_is_solusdt_symbol(const char *symbol) {
    if (!symbol || !*symbol) return false;
    if (strcasecmp(symbol, "SOLUSDT") == 0 ||
        strcasecmp(symbol, "SOL-USDT") == 0 ||
        strcasecmp(symbol, "SOL/USDT") == 0) {
        return true;
    }
    if (strcasestr(symbol, "SOLUSDT") != NULL ||
        strcasestr(symbol, "SOL-USDT") != NULL ||
        strcasestr(symbol, "SOL/USDT") != NULL) {
        return true;
    }
    return false;
}

static bool bot_is_sol_perp_symbol(const char *symbol) {
    if (!symbol || !*symbol) return false;
    if (strcasestr(symbol, "SOL") && strcasestr(symbol, "PERP")) return true;
    return false;
}

static bool bot_symbol_matches(const char *a, const char *b) {
    if (!a || !b) return false;
    while (*a && *b) {
        char ca = *a;
        char cb = *b;
        if (ca == '/' || ca == '-') {
            a++;
            continue;
        }
        if (cb == '/' || cb == '-') {
            b++;
            continue;
        }
        if (ca >= 'a' && ca <= 'z') ca -= 'a' - 'A';
        if (cb >= 'a' && cb <= 'z') cb -= 'a' - 'A';
        if (ca != cb) return false;
        a++;
        b++;
    }
    while (*a == '/' || *a == '-') a++;
    while (*b == '/' || *b == '-') b++;
    return *a == '\0' && *b == '\0';
}

static bool bot_is_allowed_hft_symbol(const char *symbol) {
    if (!symbol || !*symbol) return false;
    for (size_t i = 0; i < ALLOWED_SYMBOLS_COUNT; i++) {
        if (bot_symbol_matches(symbol, g_allowed_hft_symbols[i])) return true;
    }
    return false;
}

static bool bot_can_trade(void) {
    uint64_t now_ns = monotonic_ns();
    uint64_t last_ns = atomic_load(&g_bot_last_trade_ns);
    return now_ns >= last_ns + g_bot_trade_cooldown_ns;
}

static void bot_open_position(float entry_price) {
    g_bot_entry_price = entry_price;
    g_bot_entry_ns = monotonic_ns();
    atomic_store(&g_bot_position_open, true);
    atomic_store(&g_bot_last_trade_ns, g_bot_entry_ns);
}

static void bot_close_position(const char *reason) {
    if (!atomic_load(&g_bot_position_open)) return;
    atomic_store(&g_bot_position_open, false);
    g_bot_entry_price = 0.0f;
    g_bot_entry_ns = 0;
    char logline[256];
    snprintf(logline, sizeof(logline), "[BOT] EXIT position: %s", reason);
    push_log(logline);
}

static bool bot_should_exit_position(float current_price) {
    if (!atomic_load(&g_bot_position_open) || current_price <= 0.0f || g_bot_entry_price <= 0.0f) return false;
    uint64_t now_ns = monotonic_ns();
    float bid_qty = atomic_load_float64(&g_bybit_best_bid_qty_bits);
    float ask_qty = atomic_load_float64(&g_bybit_best_ask_qty_bits);
    bool strong_orderbook = bot_orderbook_imbalance(bid_qty, ask_qty, g_bybit_imbalance_ratio);
    bool weak_orderbook = bot_orderbook_weakness(bid_qty, ask_qty, g_bybit_exit_imbalance_ratio);

    float effective_tp = g_bot_take_profit_pct;
    float effective_sl = g_bot_stop_loss_pct;
    if (bot_internal_latency_spike()) {
        effective_sl = fminf(effective_sl, 0.35f);
        effective_tp = fminf(effective_tp, 0.8f);
    }
    if (strong_orderbook) {
        effective_tp += 0.5f;
    }
    if (weak_orderbook) {
        effective_sl = fminf(effective_sl, g_bot_stop_loss_pct * 0.5f);
    }

    float target_price = g_bot_entry_price * (1.0f + effective_tp / 100.0f);
    float stop_price = g_bot_entry_price * (1.0f - effective_sl / 100.0f);
    if (current_price >= target_price) return true;
    if (current_price <= stop_price) return true;
    if (now_ns >= g_bot_entry_ns + 30ULL * 1000000000ULL) return true;

    if (bot_internal_latency_spike() && current_price <= g_bot_entry_price * 1.002f) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[BOT] Exit due latency spike threshold %.1fms", g_bybit_internal_latency_spike_ms);
        push_log(logline);
        return true;
    }

    if (weak_orderbook && current_price <= g_bot_entry_price * 1.001f) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[BOT] Exit due orderbook weakness ask=%.5f bid=%.5f", ask_qty, bid_qty);
        push_log(logline);
        return true;
    }

    float sell_pressure = ask_qty > 0.0f ? ask_qty / bid_qty : 0.0f;
    float current_pnl_pct = ((current_price - (float)g_bot_entry_price) / (float)g_bot_entry_price) * 100.0f;
    if (sell_pressure >= g_bybit_exit_imbalance_ratio && current_pnl_pct >= SNIPER_MIN_PROFIT_TO_EXIT_PCT) {
        push_log("[BOT] SOLUSDT exit triggered by sell pressure and profit threshold");
        return true;
    }
    if (current_pnl_pct <= -SNIPER_EMERGENCY_STOP_LOSS_PCT) {
        push_log("[BOT] SOLUSDT emergency stop-loss activated");
        return true;
    }
    return false;
}

static bool bot_latency_ok(uint64_t packet_ms) {
    if (packet_ms == 0) return true;
    struct timespec now;
    clock_gettime(CLOCK_REALTIME, &now);
    double now_ms = (double)now.tv_sec * 1000.0 + (double)now.tv_nsec / 1000000.0;
    double latency_ms = now_ms - (double)packet_ms;
    if (latency_ms < 0.0) latency_ms = -latency_ms;
    if (latency_ms > g_bybit_latency_tolerance_ms) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[BOT] Latency kill-switch: %.2fms > %.2fms, dropping event", latency_ms, g_bybit_latency_tolerance_ms);
        push_log(logline);
        return false;
    }
    return true;
}

static bool bot_orderbook_imbalance(double bid_qty, double ask_qty, float ratio) {
    if (bid_qty <= 0.0 || ask_qty <= 0.0 || ratio <= 1.0f) return false;
    return bid_qty > ask_qty * (double)ratio;
}

static bool bot_orderbook_weakness(double bid_qty, double ask_qty, float ratio) {
    if (bid_qty <= 0.0 || ask_qty <= 0.0 || ratio <= 1.0f) return false;
    return ask_qty > bid_qty * (double)ratio;
}

static bool bot_internal_latency_spike(void) {
    if (g_bybit_internal_latency_spike_ms <= 0.0f) return false;
    uint64_t internal_ns = atomic_load(&g_tui.internal_latency_last_ns);
    return (double)internal_ns / 1000000.0 > (double)g_bybit_internal_latency_spike_ms;
}

static inline uint64_t monotonic_ns(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t)ts.tv_sec * 1000000000ULL + (uint64_t)ts.tv_nsec;
}

static void bot_record_internal_latency(const struct matrix_event *evt) {
    if (!evt || evt->timestamp == 0) return;
    uint64_t now_ns = monotonic_ns();
    uint64_t latency_ns = now_ns > evt->timestamp ? now_ns - evt->timestamp : 0;
    atomic_store(&g_tui.internal_latency_last_ns, latency_ns);
    atomic_fetch_add(&g_tui.internal_latency_total_ns, latency_ns);
    atomic_fetch_add(&g_tui.internal_latency_count, 1);
    if (latency_ns > (uint64_t)INTERNAL_LATENCY_ALERT_US * 1000ULL) {
        char logline[192];
        snprintf(logline, sizeof(logline), "[LATENCY] internal latency %.2fus > %u us", latency_ns / 1000.0, INTERNAL_LATENCY_ALERT_US);
        push_log(logline);
    }
}

static inline void pin_current_thread(int cpu) {
    int cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (cpu < 0 || cpu >= cores) return;
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
}

static void amx_warmup_cycle(void) {
    float A[PHASE_DIM] __attribute__((aligned(64)));
    float B[PHASE_DIM] __attribute__((aligned(64)));
    float C[PHASE_DIM * PHASE_DIM] __attribute__((aligned(64)));
    for (uint32_t i = 0; i < PHASE_DIM; i++) {
        A[i] = (float)i * 0.001f;
        B[i] = (float)(PHASE_DIM - i) * 0.001f;
    }
    matrix_outer_product(C, A, B, PHASE_DIM);
}

static void *amx_warmup_worker(void *arg) {
    (void)arg;
    pin_current_thread(1);
    struct timespec interval = { .tv_sec = 1, .tv_nsec = 0 };
    while (atomic_load(&g_running) && atomic_load(&g_amx_warmup_enabled)) {
        amx_warmup_cycle();
        nanosleep(&interval, NULL);
    }
    return NULL;
}

static float bot_score_payload(const struct matrix_event *evt) {
    float A[PHASE_DIM];
    float B[PHASE_DIM];
    static float C[PHASE_DIM * PHASE_DIM];
    if (!load_event_phase_vectors(A, B, evt, PHASE_DIM)) return 0.0f;
    memset(C, 0, sizeof(C));
    matrix_outer_product(C, A, B, PHASE_DIM);
    float score = 0.0f;
    size_t total = PHASE_DIM * PHASE_DIM;
    for (size_t i = 0; i < total; i++) score += C[i];
    return total ? score / (float)total : 0.0f;
}

static bool bot_should_send_order(const struct matrix_event *evt, float *price_out, float *liquidity_out) {
    if (!evt || !price_out || !liquidity_out) return false;
    double last_price = 0.0;
    uint64_t packet_ts = 0;
    bool decision = false;
    char symbol[64] = {0};

    if (!bot_extract_json_symbol(evt, symbol, sizeof(symbol))) return false;
    if (bot_extract_json_timestamp(evt->data, evt->payload_len, &packet_ts) && !bot_latency_ok(packet_ts)) {
        goto done;
    }
    if (!bot_extract_json_number(evt->data, evt->payload_len, "\"lastPrice\"", &last_price)) {
        goto done;
    }
    if (last_price <= 0.0) goto done;
    if (g_bybit_max_price_usdt > 0.0f && last_price > g_bybit_max_price_usdt) goto done;

    double orderbook_bid = 0.0, orderbook_bid_qty = 0.0, orderbook_ask = 0.0, orderbook_ask_qty = 0.0;
    if (!bot_extract_orderbook_levels_for_symbol(evt->data, evt->payload_len, symbol, &orderbook_bid, &orderbook_bid_qty, &orderbook_ask, &orderbook_ask_qty)) {
        orderbook_bid = atomic_load_float64(&g_bybit_best_bid_price_bits);
        orderbook_bid_qty = atomic_load_float64(&g_bybit_best_bid_qty_bits);
        orderbook_ask = atomic_load_float64(&g_bybit_best_ask_price_bits);
        orderbook_ask_qty = atomic_load_float64(&g_bybit_best_ask_qty_bits);
    }
    double liquidity = orderbook_ask_qty > 0.0 ? orderbook_ask_qty : orderbook_bid_qty;
    double orderbook_bid_qty_d = orderbook_bid_qty;
    double bid_liquidity_usdt = orderbook_bid_qty_d * orderbook_bid;
    bool allowed_symbol = bot_is_allowed_hft_symbol(symbol);
    if (allowed_symbol) {
        if (g_bybit_min_whale_wall_usdt > 0.0f && bid_liquidity_usdt > 0.0 && bid_liquidity_usdt < (double)g_bybit_min_whale_wall_usdt) goto done;
    } else if (g_bybit_min_liquidity > 0.0f && liquidity > 0.0f && liquidity < g_bybit_min_liquidity) {
        goto done;
    }
    int t_idx = find_token_index(symbol);
    if (t_idx != -1) {
        token_state_t *t_state = &g_token_states[t_idx];

        // МАТРИЧНЫЙ РАСЧЕТ ВЕСА СТЕН КИТОВ В USDT
        double ask_liquidity_usdt = orderbook_ask_qty * orderbook_ask;

        if (bot_can_trade()) {
            uint64_t now_ns = monotonic_ns();
            double buy_pressure = orderbook_ask_qty > 0.0 ? orderbook_bid_qty / orderbook_ask_qty : 0.0;
            double sell_pressure = orderbook_bid_qty > 0.0 ? orderbook_ask_qty / orderbook_bid_qty : 0.0;

            // СЕКЦИЯ 1: МАТРИЦА В РЕЖИМЕ ОЖИДАНИЯ СИГНАЛА (ВХОД В РЫНОК)
            {
                double current_spread = orderbook_ask - orderbook_bid;
                double adaptive_imbalance_ratio = (double)g_bybit_imbalance_ratio;
                if (current_spread <= 0.010001) {
                    adaptive_imbalance_ratio = 1.20;
                }
                bool funding_window = false;
                {
                    time_t now_time = time(NULL);
                    struct tm gm;
                    gmtime_r(&now_time, &gm);
                    int sec_of_day = gm.tm_hour * 3600 + gm.tm_min * 60 + gm.tm_sec;
                    const int funding_seconds[] = {0, 8 * 3600, 16 * 3600};
                    for (int i = 0; i < 3; i++) {
                        if (sec_of_day >= funding_seconds[i] - 60 && sec_of_day < funding_seconds[i]) {
                            funding_window = true;
                            break;
                        }
                    }
                }
                bool perp_tail_long = false;
                if (bot_is_solusdt_symbol(symbol)) {
                    uint64_t spot_bits = atomic_load(&g_last_sol_spot_price);
                    uint64_t perp_bits = atomic_load(&g_last_sol_perp_price);
                    double spot_last = 0.0, perp_last = 0.0;
                    memcpy(&spot_last, &spot_bits, sizeof(spot_last));
                    memcpy(&perp_last, &perp_bits, sizeof(perp_last));
                    if (spot_last > 0.0 && perp_last > 0.0) {
                        double perp_gap_pct = ((perp_last - spot_last) / spot_last) * 100.0;
                        double spot_move_pct = (((orderbook_bid + orderbook_ask) * 0.5 - spot_last) / spot_last) * 100.0;
                        if (perp_gap_pct >= 0.15 && fabs(spot_move_pct) <= 0.05) {
                            perp_tail_long = true;
                        }
                    }
                }
                if (!atomic_load(&t_state->position_open)) {
                    if (now_ns - t_state->last_trade_ns >= g_bot_trade_cooldown_ns) {
                        if ((buy_pressure >= adaptive_imbalance_ratio || perp_tail_long) && bid_liquidity_usdt >= MIN_WHALE_WALL_USDT) {
                            *price_out = orderbook_ask > 0.0 ? orderbook_ask : last_price;
                            *liquidity_out = orderbook_ask_qty > 0.0 ? orderbook_ask_qty : liquidity;
                            decision = true;

                        atomic_store(&t_state->position_open, true);
                        atomic_store(&t_state->action, ACT_BUY);

                        uint64_t price_bits;
                        double d_ask = *price_out;
                        memcpy(&price_bits, &d_ask, sizeof(double));
                        atomic_store(&t_state->entry_price_bits, price_bits);
                        t_state->last_trade_ns = now_ns;

                        char logline[192];
                        snprintf(logline, sizeof(logline), "[AMX LONG] Whale buy pressure detected. Order out. %s", symbol);
                        push_log(logline);
                        goto done;
                    }
                    else if (!funding_window && sell_pressure >= adaptive_imbalance_ratio && ask_liquidity_usdt >= MIN_WHALE_WALL_USDT) {
                        *price_out = orderbook_bid > 0.0 ? orderbook_bid : last_price;
                        *liquidity_out = orderbook_bid_qty > 0.0 ? orderbook_bid_qty : liquidity;
                        decision = true;

                        atomic_store(&t_state->position_open, true);
                        atomic_store(&t_state->action, ACT_SHORT);

                        uint64_t price_bits;
                        double d_bid = *price_out;
                        memcpy(&price_bits, &d_bid, sizeof(double));
                        atomic_store(&t_state->entry_price_bits, price_bits);
                        t_state->last_trade_ns = now_ns;

                        char logline[192];
                        snprintf(logline, sizeof(logline), "[AMX SHORT] Whale sell pressure detected! Shoting market. %s", symbol);
                        push_log(logline);
                        goto done;
                    }
                }
            }
            else {
                uint64_t r_bits = atomic_load(&t_state->entry_price_bits);
                double entry_price;
                memcpy(&entry_price, &r_bits, sizeof(double));
                bot_action_t current_action = atomic_load(&t_state->action);
                uint64_t emergency_timeout_ns = 60ull * 1000000000ull;
                bool emergency_timeout = (t_state->last_trade_ns > 0 && now_ns - t_state->last_trade_ns >= emergency_timeout_ns);

                if (entry_price > 0.0) {
                    if (current_action == ACT_BUY) {
                        double current_pnl_pct = ((orderbook_bid - entry_price) / entry_price) * 100.0;
                        bool take_profit = current_pnl_pct >= (double)g_bot_take_profit_pct;
                        bool stop_loss = current_pnl_pct <= -(double)g_bot_stop_loss_pct;
                        bool reverse_wall = (buy_pressure <= 0.5) && (current_pnl_pct >= 0.12);

                        if (take_profit || stop_loss || reverse_wall || emergency_timeout) {
                            *price_out = orderbook_bid > 0.0 ? orderbook_bid : last_price;
                            *liquidity_out = orderbook_bid_qty > 0.0 ? orderbook_bid_qty : liquidity;
                            decision = true;

                            atomic_store(&t_state->position_open, false);
                            atomic_store(&t_state->entry_price_bits, 0);
                            atomic_store(&t_state->action, ACT_SELL);
                            t_state->last_trade_ns = now_ns;

                            char logline[192];
                            snprintf(logline, sizeof(logline), "[AMX EXIT] Long position closed.%s %s PnL=%.3f%%",
                                     emergency_timeout ? " Emergency timeout triggered." : "",
                                     symbol,
                                     current_pnl_pct);
                            push_log(logline);
                            goto done;
                        }
                    }
                    else if (current_action == ACT_SHORT) {
                        double current_pnl_pct = ((entry_price - orderbook_ask) / entry_price) * 100.0;
                        bool take_profit = current_pnl_pct >= (double)g_bot_take_profit_pct;
                        bool stop_loss = current_pnl_pct <= -(double)g_bot_stop_loss_pct;
                        bool reverse_wall = (sell_pressure <= 0.5) && (current_pnl_pct >= 0.12);

                        if (take_profit || stop_loss || reverse_wall || emergency_timeout) {
                            *price_out = orderbook_ask > 0.0 ? orderbook_ask : last_price;
                            *liquidity_out = orderbook_ask_qty > 0.0 ? orderbook_ask_qty : liquidity;
                            decision = true;

                            atomic_store(&t_state->position_open, false);
                            atomic_store(&t_state->entry_price_bits, 0);
                            atomic_store(&t_state->action, ACT_COVER);
                            t_state->last_trade_ns = now_ns;

                            char logline[192];
                            snprintf(logline, sizeof(logline), "[AMX COVER] Short position covered at the bottom!%s %s PnL=%.3f%%",
                                     emergency_timeout ? " Emergency timeout triggered." : "",
                                     symbol,
                                     current_pnl_pct);
                            push_log(logline);
                            goto done;
                        }
                    }
                }
            }
        }
    }
    }
done:
    bot_record_internal_latency(evt);
    return decision;
}

static void bot_emulate_browser_motion(void) {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    uint32_t ms = 20 + (uint32_t)(ts.tv_nsec % 40);
    struct timespec delay = {0, (long)ms * 1000000L};
    nanosleep(&delay, NULL);
}

static int bot_connect_target(void) {
    struct addrinfo hints = {};
    struct addrinfo *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", g_target.port);
    if (getaddrinfo(g_target.host, port_str, &hints, &res) != 0) return -1;

    int sock = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        bot_emulate_browser_motion();
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static SSL_CTX *bot_tls_ctx(void) {
    if (g_ssl_ctx) return g_ssl_ctx;
    if (OPENSSL_init_ssl(OPENSSL_INIT_LOAD_SSL_STRINGS | OPENSSL_INIT_LOAD_CRYPTO_STRINGS, NULL) != 1) {
        push_log("[BOT] TLS initialization failed");
        return NULL;
    }
    g_ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (!g_ssl_ctx) {
        push_log("[BOT] SSL_CTX_new() failed");
        return NULL;
    }
    SSL_CTX_set_min_proto_version(g_ssl_ctx, TLS1_2_VERSION);
    SSL_CTX_set_options(g_ssl_ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3 | SSL_OP_NO_COMPRESSION | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_verify(g_ssl_ctx, SSL_VERIFY_NONE, NULL);
    return g_ssl_ctx;
}

static bool bot_tls_request(int sock, const char *payload, size_t payload_len, ssize_t *sent_out, bool drain_response);

static void bot_tls_cleanup(void) {
    if (g_ssl_ctx) {
        SSL_CTX_free(g_ssl_ctx);
        g_ssl_ctx = NULL;
    }
}

static bool bot_tls_write(int sock, const char *payload, size_t payload_len, ssize_t *sent_out) {
    if (!payload || payload_len == 0) return false;
    return bot_tls_request(sock, payload, payload_len, sent_out, false);
}

static int bot_connect_host(const char *host, uint16_t port) {
    if (!host || port == 0) return -1;
    struct addrinfo hints = {};
    struct addrinfo *res = NULL;
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;

    char port_str[8];
    snprintf(port_str, sizeof(port_str), "%u", port);
    if (getaddrinfo(host, port_str, &hints, &res) != 0) return -1;

    int sock = -1;
    for (struct addrinfo *rp = res; rp; rp = rp->ai_next) {
        bot_emulate_browser_motion();
        sock = socket(rp->ai_family, rp->ai_socktype, rp->ai_protocol);
        if (sock < 0) continue;
        int one = 1;
        setsockopt(sock, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
        setsockopt(sock, IPPROTO_TCP, TCP_QUICKACK, &one, sizeof(one));
        if (connect(sock, rp->ai_addr, rp->ai_addrlen) == 0) break;
        close(sock);
        sock = -1;
    }
    freeaddrinfo(res);
    return sock;
}

static SSL *bot_tls_connect(int sock, const char *hostname) {
    if (sock < 0) return NULL;
    SSL_CTX *ctx = bot_tls_ctx();
    if (!ctx) return NULL;

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        push_log("[BOT] SSL_new() failed");
        return NULL;
    }

    if (!SSL_set_fd(ssl, sock)) {
        push_log("[BOT] SSL_set_fd() failed");
        SSL_free(ssl);
        return NULL;
    }

    if (hostname && hostname[0] != '\0') {
        SSL_set_tlsext_host_name(ssl, hostname);
    }
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    const unsigned char alpn_11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    if (SSL_set_alpn_protos(ssl, alpn_11, sizeof(alpn_11)) != 0) {
        push_log("[BOT] SSL_set_alpn_protos() failed");
        SSL_free(ssl);
        return NULL;
    }

    int rc;
    while ((rc = SSL_connect(ssl)) != 1) {
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        char logline[320];
        snprintf(logline, sizeof(logline), "[BOT] SSL_connect() failed: %s", errbuf);
        push_log(logline);
        SSL_free(ssl);
        return NULL;
    }

    int flags = fcntl(sock, F_GETFL, 0);
    if (flags >= 0) fcntl(sock, F_SETFL, flags | O_NONBLOCK);
    return ssl;
}

static bool bot_tls_write_ssl(SSL *ssl, const char *payload, size_t payload_len, ssize_t *sent_out) {
    if (!ssl || !payload || payload_len == 0) return false;
    size_t total_sent = 0;
    const uint8_t *buf = (const uint8_t *)payload;
    while (total_sent < payload_len) {
        int written = SSL_write(ssl, buf + total_sent, (int)(payload_len - total_sent));
        if (written <= 0) {
            int err = SSL_get_error(ssl, written);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            char errbuf[256];
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            char logline[320];
            snprintf(logline, sizeof(logline), "[BOT] SSL_write() failed: %s", errbuf);
            push_log(logline);
            return false;
        }
        total_sent += (size_t)written;
    }
    if (sent_out) *sent_out = (ssize_t)total_sent;
    return true;
}

static bool bot_ws_send_text_frame(SSL *ssl, const char *payload);

static void bot_stop_bybit_ws_stream(void) {
    if (g_bybit_ws_ssl) {
        SSL_shutdown(g_bybit_ws_ssl);
        SSL_free(g_bybit_ws_ssl);
        g_bybit_ws_ssl = NULL;
    }
    if (g_bybit_ws_sock >= 0) {
        close(g_bybit_ws_sock);
        g_bybit_ws_sock = -1;
    }
}

static bool bot_start_bybit_ws_stream(void) {
    if (g_bybit_ws_ssl || g_bybit_ws_sock >= 0) return true;
    const char *connect_host = g_target.hostname[0] ? g_target.hostname : g_bybit_ws_host;
    const char *handshake_host = g_target.hostname[0] ? g_target.hostname : g_bybit_ws_host;
    const char *paths[3] = {NULL, NULL, NULL};
    int path_idx = 0;
    if (strcmp(g_target.path, "/realtime_public") == 0 || strcmp(g_target.path, "/realtime") == 0 || strcmp(g_target.path, "/v5/public/spot") == 0 || strcmp(g_target.path, "/v5/public/linear") == 0) {
        paths[path_idx++] = g_target.path;
    }
    if (g_target.path[0] == '/' && strcmp(g_target.path, "/") == 0) {
        paths[path_idx++] = "/v5/public/spot";
        paths[path_idx++] = "/v5/public/linear";
    }
    for (const char **p = g_bybit_ws_paths; *p && path_idx < 2; ++p) {
        if (paths[0] && strcmp(*p, paths[0]) == 0) continue;
        paths[path_idx++] = *p;
    }
    paths[path_idx] = NULL;

    char logline[256];
    snprintf(logline, sizeof(logline), "[BOT] Bybit WS attempt connect=%s path=%s", connect_host, g_target.path);
    push_log(logline);

    for (const char **path = paths; *path; ++path) {
        char attempt_log[256];
        snprintf(attempt_log, sizeof(attempt_log), "[BOT] Bybit WS connect host=%s handshake_path=%s", connect_host, *path);
        push_log(attempt_log);
        int sock = bot_connect_host(connect_host, 443);
        if (sock < 0) {
            snprintf(logline, sizeof(logline), "[BOT] Bybit WS connect failed for %s", connect_host);
            push_log(logline);
            continue;
        }

        SSL *ssl = bot_tls_connect(sock, handshake_host);
        if (!ssl) {
            close(sock);
            continue;
        }

        char handshake[1024] = {0};
        safe_snprintf(handshake, sizeof(handshake),
                     "GET %s HTTP/1.1\r\n"
                     "Host: %s\r\n"
                     "Upgrade: websocket\r\n"
                     "Connection: Upgrade\r\n"
                     "Sec-WebSocket-Key: %s\r\n"
                     "Sec-WebSocket-Version: 13\r\n"
                     "Sec-WebSocket-Protocol: json\r\n"
                     "Origin: https://%s\r\n"
                     "Pragma: no-cache\r\n"
                     "Cache-Control: no-cache\r\n"
                     "User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36\r\n"
                     "Accept: */*\r\n"
                     "Accept-Encoding: gzip, deflate, br\r\n"
                     "\r\n",
                     *path,
                     handshake_host,
                     g_bybit_ws_key,
                     handshake_host);
        int handshake_len = (int)strnlen(handshake, sizeof(handshake));
        char handshake_log[512];
        snprintf(handshake_log, sizeof(handshake_log), "[BOT] Bybit WS handshake request:\n%.256s", handshake);
        push_log(handshake_log);
        ssize_t sent = 0;
        if (!bot_tls_write_ssl(ssl, handshake, (size_t)handshake_len, &sent) || sent != handshake_len) {
            snprintf(logline, sizeof(logline), "[BOT] Bybit WebSocket handshake send failed for %s", *path);
            push_log(logline);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            close(sock);
            continue;
        }

        char resp[2048];
        size_t resp_len = 0;
        while (resp_len < sizeof(resp) - 1) {
            int n = SSL_read(ssl, resp + resp_len, (int)(sizeof(resp) - 1 - resp_len));
            if (n > 0) {
                resp_len += (size_t)n;
                resp[resp_len] = '\0';
                if (strstr(resp, "\r\n\r\n") != NULL) break;
                continue;
            }
            int err = SSL_get_error(ssl, n);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                usleep(10000);
                continue;
            }
            break;
        }
        resp[resp_len] = '\0';
        char response_log[512];
        snprintf(response_log, sizeof(response_log), "[BOT] Bybit WS handshake response (%zu bytes): %.256s", resp_len, resp);
        push_log(response_log);
        if (resp_len > 0 && strstr(resp, "101") != NULL) {
            const char *subscribe_payload = g_bybit_ws_subscribe_spot;
            if (strcmp(*path, "/v5/public/linear") == 0) {
                subscribe_payload = g_bybit_ws_subscribe_linear;
            }
            if (!bot_ws_send_text_frame(ssl, subscribe_payload)) {
                snprintf(logline, sizeof(logline), "[BOT] Bybit WebSocket subscribe failed for %s", *path);
                push_log(logline);
                SSL_shutdown(ssl);
                SSL_free(ssl);
                close(sock);
                return false;
            }
            g_bybit_ws_sock = sock;
            g_bybit_ws_ssl = ssl;
            snprintf(logline, sizeof(logline), "[BOT] Bybit WebSocket connected %s", *path);
            push_log(logline);
            return true;
        }

        snprintf(logline, sizeof(logline), "[BOT] Bybit WebSocket upgrade failed for %s response=%.*s", *path,
                 (int)(resp_len < 240 ? resp_len : 240), resp);
        push_log(logline);
        SSL_shutdown(ssl);
        SSL_free(ssl);
        close(sock);
    }

    return false;
}

static bool bot_ws_send_text_frame(SSL *ssl, const char *payload) {
    if (!ssl || !payload) return false;
    size_t payload_len = strnlen(payload, 1024);
    uint8_t frame[2048];
    size_t pos = 0;
    frame[pos++] = 0x81; // FIN + text frame

    if (payload_len <= 125) {
        frame[pos++] = 0x80 | (uint8_t)payload_len;
    } else if (payload_len <= 0xFFFF) {
        frame[pos++] = 0x80 | 126;
        frame[pos++] = (uint8_t)(payload_len >> 8);
        frame[pos++] = (uint8_t)payload_len;
    } else {
        frame[pos++] = 0x80 | 127;
        for (int i = 7; i >= 0; i--) {
            frame[pos++] = (uint8_t)(payload_len >> (8 * i));
        }
    }

    const uint8_t mask[4] = {0x12, 0x34, 0x56, 0x78};
    memcpy(frame + pos, mask, sizeof(mask));
    pos += sizeof(mask);

    for (size_t i = 0; i < payload_len; i++) {
        frame[pos + i] = (uint8_t)payload[i] ^ mask[i % 4];
    }
    pos += payload_len;

    ssize_t sent = 0;
    if (!bot_tls_write_ssl(ssl, (const char *)frame, pos, &sent) || (size_t)sent != pos) {
        return false;
    }
    return true;
}

static bool bot_tls_request(int sock, const char *payload, size_t payload_len, ssize_t *sent_out, bool drain_response) {
    if (!payload || payload_len == 0) return false;
    SSL_CTX *ctx = bot_tls_ctx();
    if (!ctx) return false;

    SSL *ssl = SSL_new(ctx);
    if (!ssl) {
        push_log("[BOT] SSL_new() failed");
        return false;
    }

    if (!SSL_set_fd(ssl, sock)) {
        push_log("[BOT] SSL_set_fd() failed");
        SSL_free(ssl);
        return false;
    }

    if (g_target.hostname[0] != '\0') SSL_set_tlsext_host_name(ssl, g_target.hostname);
    SSL_set_mode(ssl, SSL_MODE_AUTO_RETRY);

    const unsigned char alpn_11[] = { 8, 'h', 't', 't', 'p', '/', '1', '.', '1' };
    if (SSL_set_alpn_protos(ssl, alpn_11, sizeof(alpn_11)) != 0) {
        push_log("[BOT] SSL_set_alpn_protos() failed");
        SSL_free(ssl);
        return false;
    }

    int rc;
    while ((rc = SSL_connect(ssl)) != 1) {
        int err = SSL_get_error(ssl, rc);
        if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
        char errbuf[256];
        ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
        char logline[320];
        snprintf(logline, sizeof(logline), "[BOT] SSL_connect() failed: %s", errbuf);
        push_log(logline);
        SSL_free(ssl);
        return false;
    }

    size_t total_sent = 0;
    const uint8_t *buf = (const uint8_t *)payload;
    while (total_sent < payload_len) {
        int written = SSL_write(ssl, buf + total_sent, (int)(payload_len - total_sent));
        if (written <= 0) {
            int err = SSL_get_error(ssl, written);
            if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) continue;
            char errbuf[256];
            ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
            char logline[320];
            snprintf(logline, sizeof(logline), "[BOT] SSL_write() failed: %s", errbuf);
            push_log(logline);
            SSL_shutdown(ssl);
            SSL_free(ssl);
            return false;
        }
        total_sent += (size_t)written;
    }

    ssize_t total_received = 0;
    if (drain_response) {
        char respbuf[2048];
        int n;
        while ((n = SSL_read(ssl, respbuf, sizeof(respbuf))) > 0) {
            total_received += n;
        }
        if (n < 0) {
            int err = SSL_get_error(ssl, n);
            if (err != SSL_ERROR_ZERO_RETURN && err != SSL_ERROR_WANT_READ && err != SSL_ERROR_WANT_WRITE) {
                char errbuf[256];
                ERR_error_string_n(ERR_get_error(), errbuf, sizeof(errbuf));
                char logline[320];
                snprintf(logline, sizeof(logline), "[BOT] SSL_read() failed while draining: %s", errbuf);
                push_log(logline);
            }
        }
        char logline[256];
        snprintf(logline, sizeof(logline), "[BOT] Warmup response drained %zd bytes", total_received);
        push_log(logline);
    }

    SSL_shutdown(ssl);
    SSL_free(ssl);
    if (sent_out) *sent_out = (ssize_t)total_sent;
    return total_sent == payload_len;
}

static const char *bot_default_warmup_path(void) {
    if (g_target.path[0] && strcmp(g_target.path, "/") != 0) {
        return g_target.path;
    }
    if (bot_is_bybit_target()) {
        return "/v5/public/spot";
    }
    return "/";
}

static bool bot_warmup_get_request(void) {
    char warmup_payload[1024] = {0};
    const char *path = bot_default_warmup_path();
    char logline[256];
    snprintf(logline, sizeof(logline), "[BOT] Warmup GET %s on %s", path, g_target.hostname);
    push_log(logline);
    snprintf(warmup_payload, sizeof(warmup_payload),
             "GET %s HTTP/1.1\r\n"
             "Host: %s\r\n"
             "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0\r\n"
             "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8\r\n"
             "Accept-Language: en-US,en;q=0.9\r\n"
             "Accept-Encoding: gzip, deflate, br\r\n"
             "DNT: 1\r\n"
             "Connection: keep-alive\r\n"
             "Upgrade-Insecure-Requests: 1\r\n"
             "Sec-Fetch-Dest: document\r\n"
             "Sec-Fetch-Mode: navigate\r\n"
             "Sec-Fetch-Site: none\r\n"
             "Sec-Fetch-User: ?1\r\n"
             "Sec-CH-UA: \"Firefox\";v=118, \"Chromium\";v=126, \"Not A(Brand)\";v=99\r\n"
             "Sec-CH-UA-Mobile: ?0\r\n"
             "Sec-CH-UA-Platform: \"Linux\"\r\n"
             "\r\n",
             path,
             g_target.hostname);

    int fd = bot_connect_target();
    if (fd < 0) {
        push_log("[BOT] Warmup GET failed: connect failed");
        return false;
    }

    ssize_t sent = 0;
    bool success = bot_tls_request(fd, warmup_payload, strnlen(warmup_payload, sizeof(warmup_payload)), &sent, true);
    close(fd);
    if (!success) {
        push_log("[BOT] Warmup GET failed: TLS request failed");
    } else {
        push_log("[BOT] Warmup GET succeeded");
    }
    return success;
}

static void *bot_traffic_worker(void *arg) {
    (void)arg;
    // Give BPF uprobes time to attach (up to 2 seconds)
    for (int i = 0; i < 20; i++) {
        usleep(100000); // 100ms
        if ((atomic_load(&g_bpf_ssl_read_attached) || atomic_load(&g_bpf_ssl_read_ex_attached)) &&
            (atomic_load(&g_bpf_ssl_write_attached) || atomic_load(&g_bpf_ssl_write_ex_attached))) {
            break;
        }
    }

    if (bot_is_bybit_target()) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BOT] Using Bybit WS stream host=%s hostname=%s", g_target.host, g_target.hostname);
        push_log(logline);
        if (!bot_start_bybit_ws_stream()) {
            push_log("[BOT] Initial Bybit WebSocket stream failed");
        }
    } else if (g_target.is_https) {
        push_log("[BOT] Using HTTP warmup");
        if (!bot_warmup_get_request()) {
            push_log("[BOT] Initial warmup GET failed");
        }
    }

    while (atomic_load(&g_running)) {
        if (bot_is_bybit_target()) {
            if (g_bybit_ws_ssl) {
                char buffer[MAX_PARSER_BUF];
                int n = SSL_read(g_bybit_ws_ssl, buffer, sizeof(buffer));
                if (n > 0) {
                    continue;
                }
                int err = SSL_get_error(g_bybit_ws_ssl, n);
                if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) {
                    usleep(10000);
                    continue;
                }
                push_log("[BOT] Bybit WebSocket read closed, reconnecting");
                bot_stop_bybit_ws_stream();
                if (!bot_start_bybit_ws_stream()) {
                    usleep(100000);
                }
            } else {
                if (!bot_start_bybit_ws_stream()) {
                    usleep(100000);
                }
            }
        } else if (g_target.is_https) {
            push_log("[BOT] Using HTTP warmup");
            if (!bot_warmup_get_request()) {
                push_log("[BOT] Periodic warmup GET failed");
            }
            struct timespec interval = { .tv_sec = 5, .tv_nsec = (rand() % 500) * 1000000L };
            nanosleep(&interval, NULL);
        } else {
            usleep(100000);
        }
    }

    bot_stop_bybit_ws_stream();
    return NULL;
}

static bool bot_send_market_order(const char *side, float qty, const char *qty_str, double price_limit, token_state_t *state) {
    char tx_payload[1024] = {0};
    char body[512] = {0};
    char api_header[256] = {0};
    char signature_header[256] = {0};
    const char *path = g_target.path[0] ? g_target.path : "/";

    if (g_bybit_presigned_tx[0] != '\0') {
        snprintf(tx_payload, sizeof(tx_payload), "%s", g_bybit_presigned_tx);
    } else {
        if (qty_str && qty_str[0] != '\0') {
            if (price_limit > 0.0) {
                snprintf(body, sizeof(body), "{\"category\":\"spot\",\"symbol\":\"%s\",\"side\":\"%s\",\"orderType\":\"Market\",\"qty\":\"%s\",\"price\":\"%.4f\"}",
                         state ? state->symbol : "SOLUSDT", side, qty_str, price_limit);
            } else {
                snprintf(body, sizeof(body), "{\"category\":\"spot\",\"symbol\":\"%s\",\"side\":\"%s\",\"orderType\":\"Market\",\"qty\":\"%s\"}",
                         state ? state->symbol : "SOLUSDT", side, qty_str);
            }
        } else {
            char qty_usdt_str[32] = {0};
            double qty_usdt = (double)qty;
            double qty_usdt_rounded = round(qty_usdt * 100.0) / 100.0;
            if (fabs(qty_usdt_rounded - (double)(long long)qty_usdt_rounded) < 0.000001) {
                snprintf(qty_usdt_str, sizeof(qty_usdt_str), "%lld", (long long)qty_usdt_rounded);
            } else {
                snprintf(qty_usdt_str, sizeof(qty_usdt_str), "%.2f", qty_usdt_rounded);
                char *p = qty_usdt_str + strlen(qty_usdt_str) - 1;
                while (p > qty_usdt_str && *p == '0') *p-- = '\0';
                if (*p == '.') *p = '\0';
            }
            if (price_limit > 0.0) {
                snprintf(body, sizeof(body), "{\"category\":\"spot\",\"symbol\":\"%s\",\"side\":\"%s\",\"orderType\":\"Market\",\"quoteOrderQty\":\"%s\",\"price\":\"%.4f\"}",
                         state ? state->symbol : "SOLUSDT", side, qty_usdt_str, price_limit);
            } else {
                snprintf(body, sizeof(body), "{\"category\":\"spot\",\"symbol\":\"%s\",\"side\":\"%s\",\"orderType\":\"Market\",\"quoteOrderQty\":\"%s\"}",
                         state ? state->symbol : "SOLUSDT", side, qty_usdt_str);
            }
        }
        uint64_t timestamp_ms = 0;
        int recv_window = 5000;
        if (g_bot_api_secret[0] != '\0' && g_bot_api_key[0] != '\0') {
            struct timespec ts;
            clock_gettime(CLOCK_REALTIME, &ts);
            timestamp_ms = (uint64_t)ts.tv_sec * 1000ULL + (uint64_t)ts.tv_nsec / 1000000ULL;

            char sign_src[2048] = {0};
            snprintf(sign_src, sizeof(sign_src), "%llu%s%d%s",
                     (unsigned long long)timestamp_ms,
                     g_bot_api_key,
                     recv_window,
                     body);

            unsigned char digest[EVP_MAX_MD_SIZE];
            unsigned int digest_len = 0;
            HMAC(EVP_sha256(), g_bot_api_secret, (int)strlen(g_bot_api_secret), (unsigned char *)sign_src, strlen(sign_src), digest, &digest_len);
            char hex[EVP_MAX_MD_SIZE * 2 + 1] = {0};
            for (unsigned int i = 0; i < digest_len; i++) {
                snprintf(hex + (i * 2), sizeof(hex) - (i * 2), "%02x", digest[i]);
            }
            snprintf(signature_header, sizeof(signature_header), "X-BAPI-SIGN: %s\r\n", hex);
            snprintf(api_header, sizeof(api_header),
                     "X-BAPI-API-KEY: %s\r\n"
                     "X-BAPI-TIMESTAMP: %llu\r\n"
                     "X-BAPI-RECV-WINDOW: %d\r\n",
                     g_bot_api_key,
                     (unsigned long long)timestamp_ms,
                     recv_window);
        }

        snprintf(tx_payload, sizeof(tx_payload),
                 "POST %s HTTP/1.1\r\n"
                 "Host: %s\r\n"
                 "User-Agent: Mozilla/5.0 (X11; Linux x86_64; rv:118.0) Gecko/20100101 Firefox/118.0\r\n"
                 "Content-Type: application/json\r\n"
                 "%s"
                 "%s"
                 "Content-Length: %zu\r\n"
                 "Connection: close\r\n\r\n"
                 "%s",
                 path,
                 g_target.hostname,
                 api_header,
                 signature_header,
                 strnlen(body, sizeof(body)),
                 body);
    }

    int fd = bot_connect_target();
    if (fd < 0) {
        push_log("[BOT] Failed to open order socket");
        return false;
    }

    bool success = false;
    ssize_t sent = 0;
    char respbuf[4096] = {0};
    ssize_t response_len = 0;
    if (g_target.is_https) {
        if (!bot_warmup_get_request()) {
            push_log("[BOT] Warmup GET request failed");
        }
        SSL *ssl = bot_tls_connect(fd, g_target.hostname);
        if (!ssl) {
            push_log("[BOT] Failed to establish HTTPS order connection");
        } else {
            success = bot_tls_write_ssl(ssl, tx_payload, strnlen(tx_payload, sizeof(tx_payload)), &sent);
            if (!success) {
                push_log("[BOT] Failed to send HTTPS order payload");
            } else {
                int n;
                while ((n = SSL_read(ssl, respbuf + response_len, (int)(sizeof(respbuf) - 1 - response_len))) > 0) {
                    response_len += n;
                }
                if (response_len > 0) respbuf[response_len] = '\0';
            }
            SSL_shutdown(ssl);
            SSL_free(ssl);
        }
    } else {
        sent = write(fd, tx_payload, strnlen(tx_payload, sizeof(tx_payload)));
        success = (sent >= 0);
        if (!success) {
            push_log("[BOT] Failed to send order payload");
        } else {
            response_len = read(fd, respbuf, sizeof(respbuf) - 1);
            if (response_len > 0) respbuf[response_len] = '\0';
        }
    }

    if (success) {
        char logline[512];
        snprintf(logline, sizeof(logline), "[BOT] EXECUTE %s: %.*s | api_key=%s | keepalive=%s | sent=%zd bytes",
                 side,
                 (int)(sent < (ssize_t)sizeof(tx_payload) ? sent : (ssize_t)sizeof(tx_payload)), tx_payload,
                 g_bot_api_key[0] ? "SET" : "NONE",
                 atomic_load(&g_bybit_keepalive) ? "ON" : "OFF",
                 sent);
        push_log(logline);
        atomic_fetch_add(&g_bot_actions, 1);

        if (response_len > 0) {
            // Жесткий дебаг: печатаем сырой ответ сервера, чтобы сразу видеть 401/502/HTML и другие отклонения.
            char raw_debug[512];
            snprintf(raw_debug, sizeof(raw_debug), "[SERVER RESPONSE] %.*s",
                     (int)(response_len > 300 ? 300 : response_len), respbuf);
            push_log(raw_debug);

            double ret_code = -1.0;
            char *json_start = strchr(respbuf, '{');
            if (json_start && bot_extract_json_number((uint8_t *)json_start, strlen(json_start), "\"retCode\"", &ret_code)) {
                if ((int)ret_code != 0) {
                    success = false;
                    char ret_msg[128] = {0};
                    if (!bot_extract_json_string((uint8_t *)json_start, strlen(json_start), "\"retMsg\"", ret_msg, sizeof(ret_msg))) {
                        bot_extract_json_string((uint8_t *)json_start, strlen(json_start), "\"ret_msg\"", ret_msg, sizeof(ret_msg));
                    }
                    char errlog[384];
                    snprintf(errlog, sizeof(errlog), "[BOT] ORDER REJECTED retCode=%d retMsg=%s | side=%s | symbol=%s",
                             (int)ret_code,
                             ret_msg[0] ? ret_msg : "UNKNOWN",
                             side,
                             state ? state->symbol : "UNKNOWN");
                    push_log(errlog);
                    if (state) {
                        atomic_store(&state->position_open, false);
                        atomic_store(&state->entry_price_bits, 0);
                        atomic_store(&state->action, ACT_NONE);
                        state->last_trade_qty_str[0] = '\0';
                        state->last_trade_ns = 0;
                    }
                } else if (state && (qty_str == NULL || qty_str[0] == '\0')) {
                    char exec_qty[64] = {0};
                    char exec_price[64] = {0};

                    if (bot_extract_json_number_token_string((uint8_t *)json_start, strlen(json_start), "\"execQty\"", exec_qty, sizeof(exec_qty))) {
                        if (exec_qty[0] != '\0') {
                            safe_strncpy(state->last_trade_qty_str, exec_qty, sizeof(state->last_trade_qty_str));
                        }
                    }

                    if (bot_extract_json_number_token_string((uint8_t *)json_start, strlen(json_start), "\"execPrice\"", exec_price, sizeof(exec_price))) {
                        if (exec_price[0] != '\0') {
                            char *endptr = NULL;
                            double parsed_price = strtod(exec_price, &endptr);
                            if (endptr != exec_price && parsed_price > 0.0) {
                                uint64_t price_bits;
                                memcpy(&price_bits, &parsed_price, sizeof(price_bits));
                                atomic_store(&state->entry_price_bits, price_bits);
                            }
                        }
                    }

                    state->last_trade_ns = monotonic_ns();
                }
            } else {
                success = false;
            }
        }
    }
    close(fd);
    return success;
}

static bool bot_payload_matches(const struct matrix_event *evt) {
    if (!evt) return false;
    char symbol[64] = {0};
    if (bot_extract_json_symbol(evt, symbol, sizeof(symbol))) {
        if (bot_is_allowed_hft_symbol(symbol)) return true;
        if (payload_contains((uint8_t *)symbol, strlen(symbol), (uint8_t *)"SOL", 3)) {
            return true;
        }
    }
    for (size_t i = 0; i < ALLOWED_SYMBOLS_COUNT; i++) {
        if (payload_contains(evt->data, evt->payload_len, (uint8_t *)g_allowed_hft_symbols[i], strlen(g_allowed_hft_symbols[i]))) {
            return true;
        }
    }
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"SOLUSDT", 7)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"SOL-USDT", 8)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"SOL/USDT", 8)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"symbol=SOLUSDT", 14)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"/v5/market/orderbook?symbol=SOLUSDT", 29)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"/v5/market/depth?symbol=SOLUSDT", 26)) return true;
    if (payload_contains(evt->data, evt->payload_len, (uint8_t *)"/v5/market/ticker?symbol=SOLUSDT", 29)) return true;
    if (g_bot_target_contract_len > 0 && payload_contains(evt->data, evt->payload_len, (uint8_t *)g_bot_target_contract, g_bot_target_contract_len)) return true;
    if (g_bot_event_signature_len > 0 && payload_contains(evt->data, evt->payload_len, (uint8_t *)g_bot_event_signature, g_bot_event_signature_len)) return true;
    return bot_contains_bybit_keyword(evt);
}

static bool bot_exit_if_needed(const struct matrix_event *evt) {
    if (!evt || !atomic_load(&g_bot_position_open)) return false;
    double last_price = 0.0;
    if (!bot_extract_json_number(evt->data, evt->payload_len, "\"lastPrice\"", &last_price)) return false;
    if (last_price <= 0.0) return false;
    if (bot_should_exit_position((float)last_price)) {
        if (bot_send_market_order("SELL", g_sniper_trade_usdt > 0.0f ? g_sniper_trade_usdt : 2.0f, NULL, 0.0, NULL)) {
            bot_close_position("TP/SL/timeout");
            return true;
        }
    }
    return false;
}

static void bot_execute_auto_snipe(const struct matrix_event *evt) {
    if (!evt) return;
    float price = 0.0f;
    float liquidity = 0.0f;
    if (!bot_should_send_order(evt, &price, &liquidity)) return;
    if (!bot_can_trade()) return;
    float trade_usdt = env_f32("SNIPER_TRADE_USDT", env_f32("NEXUS_SNIPER_TRADE_USDT", 4.0f));
    if (trade_usdt <= 0.0f) trade_usdt = 4.0f;
    g_sniper_trade_usdt = trade_usdt;

    char symbol[64] = {0};
    const char *side = "BUY";
    const char *qty_str = NULL;
    double price_limit = 0.0;
    token_state_t *state = NULL;

    if (bot_extract_json_symbol(evt, symbol, sizeof(symbol))) {
        int t_idx = find_token_index(symbol);
        if (t_idx != -1) {
            state = &g_token_states[t_idx];
            bot_action_t action = atomic_load(&state->action);

            if (action == ACT_SHORT || action == ACT_SELL) {
                side = "SELL";
            } else if (action == ACT_BUY || action == ACT_COVER) {
                side = "BUY";
            }

            if (action == ACT_SELL) {
                qty_str = state->last_trade_qty_str[0] ? state->last_trade_qty_str : NULL;
            } else if (action == ACT_COVER) {
                qty_str = NULL;
            }
        }
    }

    if (strcasecmp(side, "BUY") == 0) {
        price_limit = price > 0.0f ? (double)price * (1.0 + (double)g_bot_slippage_pct) : 0.0;
    } else {
        price_limit = price > 0.0f ? (double)price * (1.0 - (double)g_bot_slippage_pct) : 0.0;
    }

    if (qty_str) {
        bot_send_market_order(side, 0.0f, qty_str, price_limit, state);
    } else {
        bot_send_market_order(side, trade_usdt, NULL, price_limit, state);
    }
}

static void bot_handle_event(const struct matrix_event *evt) {
    if (!atomic_load(&g_sniper_bot_enabled) || !evt) return;
    if (!bot_payload_matches(evt)) return;
    atomic_fetch_add(&g_bot_events_detected, 1);
    if (bot_exit_if_needed(evt)) return;
    if (atomic_load(&g_auto_snipe_enabled)) {
        bot_execute_auto_snipe(evt);
    }
}

static void bot_init(void) {
    if (!atomic_load(&g_sniper_bot_enabled)) return;

    if (g_bot_api_key[0] == '\0') {
        fprintf(stderr, "[BOT] Warning: sniper bot enabled but API key is not configured. Use --key or NEXUS_API_KEY.\n");
    } else {
        size_t key_len = strnlen(g_bot_api_key, sizeof(g_bot_api_key));
        printf("[BOT] API key configured (%zu chars, masked)\n", key_len);
    }

    if (atomic_load(&g_copy_trading_enabled) && g_copy_wallet[0] == '\0') {
        fprintf(stderr, "[BOT] Warning: copy trading enabled but no wallet is configured (use --copy-wallet or NEXUS_COPY_WALLET).\n");
    }

    if (atomic_load(&g_auto_snipe_enabled)) {
        printf("[BOT] Auto-snipe enabled\n");
    }
    printf("[BOT] Bybit imbalance ratio=%.2f exit ratio=%.2f latency-spike-ms=%.1f\n",
           g_bybit_imbalance_ratio, g_bybit_exit_imbalance_ratio, g_bybit_internal_latency_spike_ms);
    if (atomic_load(&g_anti_rug_enabled)) {
        printf("[BOT] Anti-rug/honeypot checks enabled\n");
    }
    if (atomic_load(&g_mev_protection_enabled)) {
        printf("[BOT] MEV protection enabled\n");
    }
    if (atomic_load(&g_copy_trading_enabled)) {
        printf("[BOT] Copy trading enabled\n");
    }
    if (g_bot_target_contract_len > 0) {
        printf("[BOT] Target contract filter loaded (%zu bytes)\n", g_bot_target_contract_len);
    }
    if (g_bot_event_signature_len > 0) {
        printf("[BOT] Event signature filter loaded (%zu bytes)\n", g_bot_event_signature_len);
    }
}

static const char *bot_key_status(void) {
    if (g_bot_api_key[0] == '\0') return "NONE";
    return "SET";
}

/* ============================================================================
   TARGET PARSER
============================================================================ */
static void parse_target(const char *input, target_config_t *cfg) {
    if (!input || !cfg) return;
    strncpy(cfg->target, input, TARGET_MAX_LEN - 1);
    cfg->target[TARGET_MAX_LEN-1] = '\0';
    
    const char *s = input;
    if (strncmp(s, "https://", 8) == 0) { cfg->is_https = true; s += 8; }
    else if (strncmp(s, "http://", 7) == 0) { s += 7; }
    
    char host_port[128] = {0};
    const char *slash = strchr(s, '/');
    if (slash) snprintf(host_port, sizeof(host_port), "%.*s", (int)(slash - s), s);
    else snprintf(host_port, sizeof(host_port), "%s", s);
    
    strncpy(cfg->hostname, host_port, sizeof(cfg->hostname)-1);
    cfg->hostname[sizeof(cfg->hostname)-1] = '\0';

    cfg->path[0] = '/';
    cfg->path[1] = '\0';
    if (slash) {
        snprintf(cfg->path, sizeof(cfg->path), "%s", slash);
    }

    char *colon = strchr(host_port, ':');
    if (colon) {
        *colon = '\0';
        strncpy(cfg->host, host_port, sizeof(cfg->host)-1);
        cfg->port = (uint16_t)atoi(colon + 1);
    } else {
        strncpy(cfg->host, host_port, sizeof(cfg->host)-1);
        cfg->port = cfg->is_https ? 443 : 80;
    }
    
    if (cfg->host[0] < '0' || cfg->host[0] > '9') {
        struct addrinfo hints = {.ai_family = AF_INET}, *res = NULL;
        if (getaddrinfo(cfg->host, NULL, &hints, &res) == 0) {
            inet_ntop(AF_INET, &((struct sockaddr_in*)res->ai_addr)->sin_addr, cfg->host, sizeof(cfg->host));
            freeaddrinfo(res);
        }
    }

    bot_normalize_bybit_path(cfg);
    if (!cfg->is_https && cfg->port == 443) {
        cfg->is_https = true;
    }
}

/* ============================================================================
   BACKEND DETECTION
============================================================================ */
#ifndef HWCAP2_SME2
#define HWCAP2_SME2 (1UL << 20)
#endif

static bool apple_arm_cpu(void) {
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64))
    FILE *f = fopen("/proc/cpuinfo", "r");
    if (!f) return false;
    char line[256];
    bool apple = false;
    while (fgets(line, sizeof(line), f)) {
        if ((strstr(line, "CPU implementer") && strstr(line, "0x61")) ||
            (strstr(line, "model name") && strstr(line, "Apple"))) {
            apple = true;
            break;
        }
    }
    fclose(f);
    return apple;
#else
    return false;
#endif
}

static matrix_backend_t detect_backend(void) {
#if defined(__linux__) && (defined(__aarch64__) || defined(__arm64))
    unsigned long hwcaps2 = getauxval(AT_HWCAP2);
    if (hwcaps2 & HWCAP2_SME2) return BACKEND_SME2;
    if (apple_arm_cpu()) return BACKEND_AMX;
#endif
#if defined(__APPLE__)
    return BACKEND_AMX;
#elif defined(__ARM_NEON) || defined(__aarch64__)
    return BACKEND_NEON;
#else
    return BACKEND_SCALAR;
#endif
}

static bool parse_backend_arg(const char *arg, matrix_backend_t *out) {
    if (!arg || !out) return false;
    if (strcmp(arg, "sme2") == 0) { *out = BACKEND_SME2; return true; }
    if (strcmp(arg, "amx") == 0) { *out = BACKEND_AMX; return true; }
    if (strcmp(arg, "neon") == 0) { *out = BACKEND_NEON; return true; }
    if (strcmp(arg, "scalar") == 0) { *out = BACKEND_SCALAR; return true; }
    return false;
}

static bool is_valid_bpf_mode(const char *mode) {
    return mode && (strcmp(mode, "socket") == 0 || strcmp(mode, "auto") == 0);
}

/* ============================================================================
   PERF COUNTERS
============================================================================ */
static bool perf_init(perf_counters_t *p) {
    struct perf_event_attr pe = {.type = PERF_TYPE_HARDWARE, .size = sizeof(pe), .disabled = 1, .exclude_kernel = 1, .exclude_hv = 1};
    pe.config = PERF_COUNT_HW_CPU_CYCLES;
    p->fd_cycles = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    pe.config = PERF_COUNT_HW_INSTRUCTIONS;
    p->fd_instr = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    pe.config = PERF_COUNT_HW_CACHE_MISSES;
    p->fd_cache = (int)syscall(SYS_perf_event_open, &pe, 0, -1, -1, PERF_FLAG_FD_CLOEXEC);
    
    if (p->fd_cycles < 0) return false;
    ioctl(p->fd_cycles, PERF_EVENT_IOC_RESET, 0); ioctl(p->fd_cycles, PERF_EVENT_IOC_ENABLE, 0);
    ioctl(p->fd_instr, PERF_EVENT_IOC_RESET, 0); ioctl(p->fd_instr, PERF_EVENT_IOC_ENABLE, 0);
    if (p->fd_cache >= 0) { ioctl(p->fd_cache, PERF_EVENT_IOC_RESET, 0); ioctl(p->fd_cache, PERF_EVENT_IOC_ENABLE, 0); }
    
    read(p->fd_cycles, &p->base_cycles, sizeof(p->base_cycles));
    read(p->fd_instr, &p->base_instr, sizeof(p->base_instr));
    if (p->fd_cache >= 0) read(p->fd_cache, &p->base_cache, sizeof(p->base_cache));
    return true;
}

static void perf_update(perf_counters_t *p, uint64_t *cycles, uint64_t *instr, uint64_t *cache) {
    uint64_t c, i, m;
    if (read(p->fd_cycles, &c, sizeof(c)) == sizeof(c)) *cycles = c - p->base_cycles;
    if (read(p->fd_instr, &i, sizeof(i)) == sizeof(i)) *instr = i - p->base_instr;
    if (p->fd_cache >= 0 && read(p->fd_cache, &m, sizeof(m)) == sizeof(m)) *cache = m - p->base_cache;
}

/* ============================================================================
   REAL-TIME TUI (ANSI terminal with colors and dynamic log layout)
============================================================================ */
#define ANSI_RESET      "\033[0m"
#define ANSI_BOLD       "\033[1m"
#define ANSI_GREEN      "\033[32m"
#define ANSI_YELLOW     "\033[33m"
#define ANSI_CYAN       "\033[36m"
#define ANSI_MAGENTA    "\033[35m"
#define ANSI_RED        "\033[31m"
#define ANSI_WHITE      "\033[37m"
#define TUI_LOG_ROWS 16

static void render_tui(void) {
    uint64_t latency_count = atomic_load(&g_tui.e2e_latency_count);
    uint64_t latency_total = atomic_load(&g_tui.e2e_latency_total_ns);
    uint64_t latency_last = atomic_load(&g_tui.e2e_latency_last_ns);
    uint64_t internal_latency_last = atomic_load(&g_tui.internal_latency_last_ns);
    double avg_latency_us = latency_count ? (double)latency_total / latency_count / 1000.0 : 0.0;
    uint64_t dropped = g_bpf_stats_fd >= 0 ? bpf_stats_read(METRIC_RINGBUF_FULL) : atomic_load(&g_tui.dropped_ringbuf);
    uint64_t partial = atomic_load(&g_tui.partial_invalid);
    uint64_t events = atomic_load(&g_tui.events_total);
    float best_bid = atomic_load_float64(&g_bybit_best_bid_price_bits);
    float best_bid_qty = atomic_load_float64(&g_bybit_best_bid_qty_bits);
    float best_ask = atomic_load_float64(&g_bybit_best_ask_price_bits);
    float best_ask_qty = atomic_load_float64(&g_bybit_best_ask_qty_bits);
    uint64_t ssl_read_count = atomic_load(&g_ssl_read_events);
    uint64_t ssl_write_count = atomic_load(&g_ssl_write_events);
    uint64_t ssl_read_ex_count = atomic_load(&g_ssl_read_ex_events);
    uint64_t ssl_write_ex_count = atomic_load(&g_ssl_write_ex_events);

    const char *ssl_r_status = (atomic_load(&g_bpf_ssl_read_attached) || atomic_load(&g_bpf_ssl_read_ex_attached)) ? "OK" : "NO";
    const char *ssl_w_status = (atomic_load(&g_bpf_ssl_write_attached) || atomic_load(&g_bpf_ssl_write_ex_attached)) ? "OK" : "NO";
    const char *ssl_rx_status = (atomic_load(&g_bpf_ssl_read_ex_attached) || ssl_read_ex_count > 0) ? "OK" : "NO";
    const char *ssl_wx_status = (atomic_load(&g_bpf_ssl_write_ex_attached) || ssl_write_ex_count > 0) ? "OK" : "NO";

    printf("\033[H\033[2J");
    printf(ANSI_CYAN "================================================================================\n" ANSI_RESET);
    printf(ANSI_CYAN ANSI_BOLD "PEC MATRIX ENGINE" ANSI_RESET "\n");
    printf(ANSI_CYAN "================================================================================\n" ANSI_RESET);
    printf(ANSI_GREEN "TARGET:" ANSI_WHITE " %s\n" ANSI_RESET, g_target.host);
    printf(ANSI_GREEN "BACKEND:" ANSI_WHITE " %s\n" ANSI_RESET,
           g_backend == BACKEND_SME2 ? "SME2" : g_backend == BACKEND_AMX ? "AMX" : g_backend == BACKEND_NEON ? "NEON" : "SCALAR");

    pthread_mutex_lock(&g_tui.log_mutex);
    if (g_tui.startup_message[0]) {
        printf(ANSI_YELLOW "PROBES:" ANSI_WHITE " %s\n" ANSI_RESET, g_tui.startup_message);
        g_tui.startup_message[0] = '\0';
    }
    pthread_mutex_unlock(&g_tui.log_mutex);

    printf(ANSI_CYAN "----------------------------------------------------------------------\n" ANSI_RESET);
    printf(ANSI_MAGENTA "COLLAPSES:" ANSI_WHITE " %-8" PRIu64 "  " ANSI_MAGENTA "CYCLES:" ANSI_WHITE " %-10" PRIu64 "  " ANSI_MAGENTA "INST:" ANSI_WHITE " %-8" PRIu64 "\n" ANSI_RESET,
           atomic_load(&g_total_collapses), atomic_load(&g_tui.cycles_delta), atomic_load(&g_tui.inst_delta));
    printf(ANSI_MAGENTA "PEAK_RES:" ANSI_WHITE " %-8.4f  " ANSI_MAGENTA "CACHE:" ANSI_WHITE " %-10" PRIu64 "  " ANSI_MAGENTA "LAT_AVG:" ANSI_WHITE " %-7.1fus\n" ANSI_RESET,
           atomic_load(&g_peak_resonance), atomic_load(&g_tui.cache_miss_delta), avg_latency_us);
    printf(ANSI_MAGENTA "DROPPED:" ANSI_WHITE " %-9" PRIu64 "  " ANSI_MAGENTA "PARTIAL:" ANSI_WHITE " %-9" PRIu64 "  " ANSI_MAGENTA "EVENTS:" ANSI_WHITE " %-7" PRIu64 "\n" ANSI_RESET,
           dropped, partial, events);
    printf(ANSI_MAGENTA "LAT_LAST:" ANSI_WHITE " %-8.1fus  " ANSI_MAGENTA "INT_LAST:" ANSI_WHITE " %-8.1fus  " ANSI_MAGENTA "GOD:" ANSI_WHITE " %-3s\n" ANSI_RESET,
           (double)latency_last / 1000.0, (double)internal_latency_last / 1000.0,
           atomic_load(&g_bpf_god_mode) ? "ON" : "OFF");
    printf(ANSI_CYAN "----------------------------------------------------------------------\n" ANSI_RESET);
    printf(ANSI_YELLOW "HANDSHAKE:" ANSI_WHITE " SSL_R=%-3s(%" PRIu64 ") SSL_W=%-3s(%" PRIu64 ") SSL_RX=%-3s(%" PRIu64 ") SSL_WX=%-3s(%" PRIu64 ")\n" ANSI_RESET,
           ssl_r_status, ssl_read_count,
           ssl_w_status, ssl_write_count,
           ssl_rx_status, ssl_read_ex_count,
           ssl_wx_status, ssl_write_ex_count);
    printf(ANSI_YELLOW "CONNECT:" ANSI_WHITE " BID=%9.5f x %-8.5f  ASK=%9.5f x %-8.5f\n" ANSI_RESET,
           best_bid, best_bid_qty, best_ask, best_ask_qty);
    float solusdt_bid = atomic_load_float64(&g_solusdt_best_bid_price_bits);
    float solusdt_bid_qty = atomic_load_float64(&g_solusdt_best_bid_qty_bits);
    float solusdt_ask = atomic_load_float64(&g_solusdt_best_ask_price_bits);
    float solusdt_ask_qty = atomic_load_float64(&g_solusdt_best_ask_qty_bits);
    printf(ANSI_YELLOW "SOLUSDT:" ANSI_WHITE " BID=%9.5f x %-8.5f  ASK=%9.5f x %-8.5f\n" ANSI_RESET,
           solusdt_bid, solusdt_bid_qty, solusdt_ask, solusdt_ask_qty);
    printf(ANSI_YELLOW "BOT_STATUS:" ANSI_WHITE " %s  KEY=%-4s  POS=%-4s  EVTS=%-5" PRIu64 "  ACT=%-5" PRIu64 "\n" ANSI_RESET,
           atomic_load(&g_sniper_bot_enabled) ? "ENABLED" : "OFF",
           bot_key_status(),
           atomic_load(&g_bot_position_open) ? "OPEN" : "WAIT",
           atomic_load(&g_bot_events_detected),
           atomic_load(&g_bot_actions));
    char bot_mode[64] = {0};
    if (atomic_load(&g_bot_direct_splice)) strcat(bot_mode, "SPLICE ");
    if (atomic_load(&g_bot_wormhole)) strcat(bot_mode, "WORMHOLE ");
    if (atomic_load(&g_bot_x11_stealth)) strcat(bot_mode, "X11/11");
    if (!bot_mode[0]) snprintf(bot_mode, sizeof(bot_mode), "NORMAL");
    printf(ANSI_YELLOW "BOT_MODE:" ANSI_WHITE " %s\n" ANSI_RESET, bot_mode);
    printf(ANSI_CYAN "----------------------------------------------------------------------\n" ANSI_RESET);
    printf(ANSI_GREEN "LIVE LOG (latest events)" ANSI_RESET "\n");
    printf(ANSI_CYAN "----------------------------------------------------------------------\n" ANSI_RESET);
    printf(ANSI_GREEN "LAST EVENT:" ANSI_WHITE " %.74s\n" ANSI_RESET, g_tui.last_event);
    printf(ANSI_CYAN "----------------------------------------------------------------------\n" ANSI_RESET);

    pthread_mutex_lock(&g_tui.log_mutex);
    size_t idx = atomic_load(&g_tui.log_idx);
    size_t scan_line = idx == 0 ? TUI_LINES - 1 : idx - 1;
    size_t rendered = 0;
    for (size_t i = 0; i < TUI_LINES && rendered < TUI_LOG_ROWS; ++i) {
        if (g_tui.log_buffer[scan_line][0] && bpf_log_is_event(g_tui.log_buffer[scan_line])) {
            const char *color = ANSI_WHITE;
            if (strstr(g_tui.log_buffer[scan_line], "SSL_READ")) color = ANSI_GREEN;
            else if (strstr(g_tui.log_buffer[scan_line], "SSL_WRITE")) color = ANSI_YELLOW;
            else if (strstr(g_tui.log_buffer[scan_line], "ORDERBOOK") || strstr(g_tui.log_buffer[scan_line], "STAKAN")) color = ANSI_CYAN;
            else if (strstr(g_tui.log_buffer[scan_line], "BYBIT")) color = ANSI_MAGENTA;
            printf(ANSI_CYAN "| " ANSI_RESET "%s%-74.74s" ANSI_RESET ANSI_CYAN " |\n" ANSI_RESET,
                   color, g_tui.log_buffer[scan_line]);
            rendered++;
        }
        scan_line = scan_line == 0 ? TUI_LINES - 1 : scan_line - 1;
    }
    if (rendered == 0) {
        printf(ANSI_CYAN "| " ANSI_WHITE "%-74s" ANSI_CYAN " |\n" ANSI_RESET, "No events yet...");
    }
    pthread_mutex_unlock(&g_tui.log_mutex);

    printf(ANSI_CYAN "================================================================================\n" ANSI_RESET);
    fflush(stdout);
}

static inline bool bpf_log_is_event(const char *msg) {
    if (!msg) return false;
    if (strcmp(msg, "[BPF] HEARTBEAT event") == 0) return true;
    if (strncmp(msg, "[BPF] ORDERBOOK", 15) == 0) return true;
    if (strncmp(msg, "[BPF] STAKAN", 11) == 0) return true;
    if (strncmp(msg, "[BPF] HTTP/JSON body", 18) == 0) return true;
    if (strncmp(msg, "[BPF] BYBIT KEYWORD", 17) == 0) return true;
    if (strncmp(msg, "[BPF] BYBIT JSON payload", 22) == 0) return true;
    if (strncmp(msg, "[BPF] EVENT type=SSL_", 18) == 0) return true;
    if (strncmp(msg, "[BPF] EVENT type=SYSCALL_SEND", 27) == 0) return true;
    return false;
}

static void update_last_event(const char *msg) {
    pthread_mutex_lock(&g_tui.log_mutex);
    snprintf(g_tui.last_event, sizeof(g_tui.last_event), "%s", msg);
    pthread_mutex_unlock(&g_tui.log_mutex);
}

static void push_log(const char *msg) {
    if (!bpf_log_is_event(msg)) return;
    pthread_mutex_lock(&g_tui.log_mutex);

    // Deduplication: don't log the same event if it is already present in the visible history.
    for (size_t i = 0; i < TUI_LINES; ++i) {
        if (g_tui.log_buffer[i][0] && strcmp(g_tui.log_buffer[i], msg) == 0) {
            pthread_mutex_unlock(&g_tui.log_mutex);
            return;
        }
    }

    size_t idx = atomic_fetch_add(&g_tui.log_idx, 1) % TUI_LINES;
    snprintf(g_tui.log_buffer[idx], sizeof(g_tui.log_buffer[0]), "%s", msg);
    snprintf(g_tui.last_event, sizeof(g_tui.last_event), "%s", msg);
    pthread_mutex_unlock(&g_tui.log_mutex);
}

/* ============================================================================
   MATRIX / PHOTONIC ENGINE
============================================================================ */
static inline void matrix_outer_product_scalar(float *C, const float *A, const float *B, uint32_t dim) {
    for (uint32_t i = 0; i < dim; i++) {
        float ai = A[i];
        for (uint32_t j = 0; j < dim; j++) {
            C[i * dim + j] += ai * B[j];
        }
    }
}

#ifdef __ARM_FEATURE_SVE
static void matrix_outer_product_sme2(float *C, const float *A, const float *B, uint32_t dim) {
    size_t vl = svcntw();

    /* Inline SME2 FMOPA path: direct ZA outer-product update using SVE assembly. */
    for (uint32_t i = 0; i < dim; i++) {
        float ai = A[i];
        float bi = B[i];
        for (uint32_t j = 0; j < dim; j += vl) {
            const float *bptr = &B[j];
            const float *aptr = &A[j];
            float *cptr = &C[i * dim + j];
            __asm__ volatile (
                "ptrue p0.b\n"
                "ld1w { z0.s }, p0/z, [%[bptr]]\n"
                "dup z1.s, %w[ai]\n"
                "ld1w { z2.s }, p0/z, [%[cptr]]\n"
                "fmopa z2.s, z1.s, z0.s\n"
                "ld1w { z3.s }, p0/z, [%[aptr]]\n"
                "dup z4.s, %w[bi]\n"
                "fmopa z2.s, z4.s, z3.s\n"
                "fmopa z2.s, z1.s, z3.s\n"
                "st1w { z2.s }, p0, [%[cptr]]\n"
                :
                : [bptr] "r" (bptr), [aptr] "r" (aptr), [cptr] "r" (cptr), [ai] "r" (ai), [bi] "r" (bi)
                : "memory", "p0", "z0", "z1", "z2", "z3", "z4"
            );
        }
    }
}

static void za_tile_sme2(float *C, const float *A, const float *B, uint32_t dim) {
    size_t vl = svcntw();
    for (uint32_t i = 0; i < dim; i++) {
        float ai = A[i];
        float bi = B[i];
        for (uint32_t j = 0; j < dim; j += vl) {
            const float *bptr = &B[j];
            const float *aptr = &A[j];
            float *cptr = &C[i * dim + j];
            __asm__ volatile (
                "ptrue p0.b\n"
                "ld1w { z0.s }, p0/z, [%[bptr]]\n"
                "ld1w { z3.s }, p0/z, [%[aptr]]\n"
                "dup z1.s, %w[ai]\n"
                "dup z4.s, %w[bi]\n"
                "ld1w { z2.s }, p0/z, [%[cptr]]\n"
                "fmopa z2.s, z1.s, z0.s\n"
                "fmopa z2.s, z4.s, z3.s\n"
                "fmopa z2.s, z1.s, z3.s\n"
                "fmopa z2.s, z4.s, z0.s\n"
                "st1w { z2.s }, p0, [%[cptr]]\n"
                :
                : [bptr] "r" (bptr), [aptr] "r" (aptr), [cptr] "r" (cptr), [ai] "r" (ai), [bi] "r" (bi)
                : "memory", "p0", "z0", "z1", "z2", "z3", "z4"
            );
        }
    }
}

static void za_tensor_collapse_sme2(float *C, const float *A, const float *B, uint32_t dim) {
    za_tile_sme2(C, A, B, dim);
}
#endif

static inline void matrix_outer_product_amx(float *C, const float *A, const float *B, uint32_t dim) {
#if defined(__ARM_NEON) || defined(__aarch64__)
    for (uint32_t i = 0; i < dim; i++) {
        float32x4_t va = vdupq_n_f32(A[i]);
        uint32_t j = 0;
        for (; j + 4 <= dim; j += 4) {
            float32x4_t vB = vld1q_f32(&B[j]);
            float32x4_t vC = vld1q_f32(&C[i * dim + j]);
            vC = vfmaq_f32(vC, vB, va);
            vst1q_f32(&C[i * dim + j], vC);
        }
        for (; j < dim; j++) {
            C[i * dim + j] += A[i] * B[j];
        }
    }
#else
    matrix_outer_product_scalar(C, A, B, dim);
#endif
}

static inline void matrix_outer_product(float *C, const float *A, const float *B, uint32_t dim) {
    if (g_backend == BACKEND_SME2) {
#ifdef __ARM_FEATURE_SVE
        matrix_outer_product_sme2(C, A, B, dim);
#else
        matrix_outer_product_scalar(C, A, B, dim);
#endif
    } else if (g_backend == BACKEND_AMX) {
        matrix_outer_product_amx(C, A, B, dim);
    } else {
        matrix_outer_product_scalar(C, A, B, dim);
    }
}

static bool load_event_phase_vectors(float *A, float *B, const struct matrix_event *evt, uint32_t dim) {
    if (!evt || evt->payload_len < 16) return false;
    const uint32_t *src32 = (const uint32_t *)evt->data;
    uint32_t words = evt->payload_len / sizeof(uint32_t);
    if (words < 4) return false;

    if ((evt->proto_hint == 1 || evt->proto_hint == 2) && evt->payload_len >= 9) {
        uint32_t frame_len = ((uint32_t)evt->data[0] << 16) |
                             ((uint32_t)evt->data[1] << 8) |
                             (uint32_t)evt->data[2];
        if (frame_len > 65536) return false;
    }
    if (evt->proto_hint == 2 && evt->payload_len >= 5) {
        uint16_t tls_len = ((uint16_t)evt->data[3] << 8) |
                           (uint16_t)evt->data[4];
        if (tls_len > 0x3FFF) return false;
    }

    for (uint32_t i = 0; i < dim; i++) {
        uint32_t a_idx = i % words;
        uint32_t b_idx = (i + words / 2) % words;
        uint32_t rawA = src32[a_idx];
        uint32_t rawB = src32[b_idx];
        float fa = ((float)(rawA & 0xFFFFFF) / 16777215.0f) * 2.0f - 1.0f;
        float fb = ((float)(rawB & 0xFFFFFF) / 16777215.0f) * 2.0f - 1.0f;
        A[i] = sinf(fa * 3.1415927f + 0.27f) * (0.7f + 0.3f * cosf(fb * 2.1f));
        B[i] = cosf(fb * 3.1415927f - 0.19f) * (0.7f + 0.3f * sinf(fa * 1.9f));
    }
    return true;
}

static inline void build_complex_phase_vectors(float *Ar, float *Ai, float *Br, float *Bi, const float *A, const float *B, uint32_t dim) {
    for (uint32_t i = 0; i < dim; i++) {
        float x = A[i];
        float y = B[i];
        Ar[i] = cosf(x * 1.17f + 0.31f);
        Ai[i] = sinf(x * 0.93f - 0.19f);
        Br[i] = cosf(y * 0.83f + 0.27f);
        Bi[i] = sinf(y * 1.09f - 0.21f);
    }
}

static inline void complex_photon_reduce(float *C, const float *Ar, const float *Ai, const float *Br, const float *Bi, uint32_t dim) {
    float temp[PHASE_DIM * PHASE_DIM];

    memset(C, 0, dim * dim * sizeof(float));
    matrix_outer_product(C, Ar, Br, dim);

    memset(temp, 0, dim * dim * sizeof(float));
    matrix_outer_product(temp, Ai, Bi, dim);
    for (uint32_t k = 0; k < dim * dim; k++) C[k] -= temp[k];

    memset(temp, 0, dim * dim * sizeof(float));
    matrix_outer_product(temp, Ar, Bi, dim);
    for (uint32_t k = 0; k < dim * dim; k++) C[k] += temp[k] * 0.34f;

    memset(temp, 0, dim * dim * sizeof(float));
    matrix_outer_product(temp, Ai, Br, dim);
    for (uint32_t k = 0; k < dim * dim; k++) C[k] += temp[k] * 0.34f;

    memset(temp, 0, dim * dim * sizeof(float));
    matrix_outer_product(temp, Br, Ar, dim);
    for (uint32_t k = 0; k < dim * dim; k++) C[k] += temp[k] * 0.18f;
}

static void sme2_keep_alive(void) {
#ifdef __ARM_FEATURE_SVE
    __asm__ volatile("smstart sm" ::: "memory");
#endif
}

static void sme2_shutdown(void) {
#ifdef __ARM_FEATURE_SVE
    __asm__ volatile("smstop sm" ::: "memory");
#endif
}

static inline bool za_tensor_collapse(float *C, const struct matrix_event *evt, uint32_t dim) {
    float A[PHASE_DIM] __attribute__((aligned(64)));
    float B[PHASE_DIM] __attribute__((aligned(64)));
    if (!load_event_phase_vectors(A, B, evt, dim)) return false;

    if (g_backend == BACKEND_SME2 || g_backend == BACKEND_AMX) {
        photon_virtualization_collapse(C, A, B, dim);
        return true;
    }

    matrix_outer_product(C, A, B, dim);
    matrix_outer_product_scalar(C, B, A, dim);
    for (uint32_t i = 0; i < dim; i++) {
        float ai = A[i] * 0.25f;
        for (uint32_t j = 0; j < dim; j++) {
            C[i * dim + j] += ai * A[j];
        }
    }
    return true;
}

static inline float resonance_peak(const float *matrix, uint32_t dim) {
    float peak = 0.0f;
    for (uint32_t i = 0; i < dim * dim; i++) {
        float v = fabsf(matrix[i]);
        if (v > peak) peak = v;
    }
    return peak;
}

#ifdef __ARM_FEATURE_SVE
static inline void sme2_photon_virtualize(float *C, const float *A, const float *B, uint32_t dim) {
    float Ar[PHASE_DIM] __attribute__((aligned(64)));
    float Ai[PHASE_DIM] __attribute__((aligned(64)));
    float Br[PHASE_DIM] __attribute__((aligned(64)));
    float Bi[PHASE_DIM] __attribute__((aligned(64)));

    build_complex_phase_vectors(Ar, Ai, Br, Bi, A, B, dim);
    complex_photon_reduce(C, Ar, Ai, Br, Bi, dim);

    for (uint32_t i = 0; i < dim; i++) {
        float phaseMix = sinf(A[i] * 0.73f + B[i] * 1.13f);
        float phaseBias = cosf(B[i] * 0.87f - A[i] * 0.19f);
        for (uint32_t j = 0; j < dim; j++) {
            C[i * dim + j] += phaseMix * phaseBias * 0.18f;
            C[j * dim + i] -= phaseMix * 0.12f;
        }
    }
}
#endif

static inline void photon_virtualization_collapse(float *C, const float *A, const float *B, uint32_t dim) {
    float Ar[PHASE_DIM] __attribute__((aligned(64)));
    float Ai[PHASE_DIM] __attribute__((aligned(64)));
    float Br[PHASE_DIM] __attribute__((aligned(64)));
    float Bi[PHASE_DIM] __attribute__((aligned(64)));
    build_complex_phase_vectors(Ar, Ai, Br, Bi, A, B, dim);

    if (g_backend == BACKEND_SME2) {
#ifdef __ARM_FEATURE_SVE
        sme2_photon_virtualize(C, A, B, dim);
#else
        complex_photon_reduce(C, Ar, Ai, Br, Bi, dim);
#endif
    } else if (g_backend == BACKEND_AMX) {
        complex_photon_reduce(C, Ar, Ai, Br, Bi, dim);
    } else {
        matrix_outer_product(C, A, B, dim);
        matrix_outer_product_scalar(C, B, A, dim);
    }
}

/* ============================================================================
   CHANNEL LOGIC
============================================================================ */
static void channel_init(pec_channel_t *ch, uint64_t seed) {
    uint32_t s = (uint32_t)(seed ^ 0x9E3779B9);
    for (int i = 0; i < PHASE_DIM; i++) {
        s = s * 1103515245U + 12345U;
        ch->phase_state[i] = ((float)(s & 0xFFFF) / 65535.0f - 0.5f) * 2.0f;
        s = s * 1103515245U + 12345U;
        ch->amplitude[i] = 0.4f + 0.6f * ((float)(s & 0xFFFF) / 65535.0f);
    }
    memset(ch->interference_map, 0, sizeof(ch->interference_map));
    ch->collapses = 0; ch->cycles = 0; ch->last_coherence = 0.0f;
    ch->last_peak = 0.0f;
    ch->adaptive_thresh = COLLAPSE_THRESH;
    ch->threshold_drift = COLLAPSE_THRESH;
}

static bool channel_process(pec_channel_t *ch, float thresh) {
    bool collapsed = false;
    float max_coh = 0.0f;
    float active_thresh = fmaxf(ch->adaptive_thresh, thresh);
    
    for (int c = 0; c < INTERFERENCE_CYCLES; c++) {
        photon_virtualization_collapse(ch->interference_map, ch->phase_state, ch->amplitude, PHASE_DIM);
        float peak = resonance_peak(ch->interference_map, PHASE_DIM);
        if (peak > max_coh) max_coh = peak;
        ch->last_peak = peak;
        atomic_store(&g_peak_resonance, peak);
        for (int i = 0; i < PHASE_DIM; i++)
            ch->amplitude[i] = ch->amplitude[i] * 0.98f + ch->phase_state[i] * 0.02f;
    }
    
    ch->last_coherence = max_coh;
    if (max_coh > active_thresh) {
        collapsed = true;
        ch->collapses++;
        atomic_fetch_add(&g_total_collapses, 1);
        for (int i = 0; i < PHASE_DIM; i++) {
            ch->phase_state[i] = ch->phase_state[i] * -0.35f +
                                 (((float)(rand() & 0xFFFF) / 65535.0f) - 0.5f) * 0.15f;
        }
        ch->adaptive_thresh += ADAPTIVE_LEARN_RATE + (max_coh - active_thresh) * 0.01f;
    } else {
        ch->adaptive_thresh -= ADAPTIVE_LEARN_RATE * 0.35f;
    }
    ch->threshold_drift += (max_coh - ch->threshold_drift) * ADAPTIVE_DRIFT_RATE;
    ch->adaptive_thresh = fminf(fmaxf(ch->adaptive_thresh, ADAPTIVE_THRESH_MIN), ADAPTIVE_THRESH_MAX);
    ch->cycles++;
    return collapsed;
}

/* ============================================================================
   IPC / RINGBUF
============================================================================ */
static int ipc_init(void) {
    g_shm_fd = shm_open(SHM_NAME, O_CREAT | O_RDWR, 0666);
    if (g_shm_fd < 0) return -1;
    if (ftruncate(g_shm_fd, SHM_SIZE) < 0) { close(g_shm_fd); return -1; }
    g_shm = mmap(NULL, SHM_SIZE, PROT_READ | PROT_WRITE, MAP_SHARED, g_shm_fd, 0);
    if (g_shm == MAP_FAILED) { close(g_shm_fd); return -1; }
    memset(g_shm, 0, SHM_SIZE);
    atomic_store(&g_shm->state, COLLAPSE_IDLE);
    g_eventfd = eventfd(0, EFD_CLOEXEC | EFD_NONBLOCK);
    return (g_eventfd < 0) ? -1 : 0;
}

static void ipc_signal_collapse(uint64_t id, float coh) {
    if (!g_shm) return;
    collapse_state_t old = atomic_load(&g_shm->state);
    if (old == COLLAPSE_IDLE || old == COLLAPSE_VERIFIED || old == COLLAPSE_SUBMITTED) {
        atomic_store(&g_shm->state, COLLAPSE_PENDING);
        g_shm->collapse_id = id;
        g_shm->coherence = coh;
        g_shm->phase_hash = (uint32_t)(id * 0x9E3779B9);
        g_shm->timestamp_ns = get_time_ns();
        g_shm->last_updated_ns = g_shm->timestamp_ns;
        if (g_eventfd >= 0) eventfd_write(g_eventfd, 1);
    }
}

static size_t env_size(const char *name, size_t def) {
    const char *value = getenv(name);
    if (!value || !*value) return def;
    char *end = NULL;
    unsigned long long v = strtoull(value, &end, 0);
    return (end && *end == '\0') ? (size_t)v : def;
}

static const char *portable_strerror_r(int err, char *buf, size_t len) {
#ifdef __GLIBC__
    const char *msg = strerror_r(err, buf, len);
    return msg ? msg : buf;
#else
    return strerror_r(err, buf, len) == 0 ? buf : "Unknown error";
#endif
}

static struct bpf_program *find_bpf_program(struct bpf_object *obj, const char *const names[], size_t name_count) {
    if (!obj || !names || name_count == 0) return NULL;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        const char *sec = bpf_program__section_name(prog);
        for (size_t i = 0; i < name_count; i++) {
            if ((name && strcmp(name, names[i]) == 0) || (sec && strcmp(sec, names[i]) == 0)) {
                return prog;
            }
        }
    }
    return NULL;
}

static void log_bpf_programs(struct bpf_object *obj) {
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        const char *name = bpf_program__name(prog);
        const char *sec = bpf_program__section_name(prog);
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] Found prog name='%s' section='%s'", name ? name : "(null)", sec ? sec : "(null)");
        fprintf(stderr, "%s\n", logline);
        push_log(logline);
    }
}

static struct bpf_link *attach_uprobe_prog_by_program(struct bpf_program *prog, const char *binary_path, size_t func_offset, const char *desc, bool retprobe) {
    if (!prog || !binary_path) return NULL;

    struct bpf_link *link = NULL;
    if (func_offset != 0) {
        link = bpf_program__attach_uprobe(prog, retprobe, -1, binary_path, func_offset);
    }
    if (!link) {
        link = bpf_program__attach_uprobe(prog, retprobe, -1, binary_path, 0);
    }
    if (!link) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] Failed to attach %s %sprobe %s@0x%zx: %s", desc, retprobe ? "ret" : "", binary_path, func_offset, strerror(errno));
        fprintf(stderr, "%s\n", logline);
        push_log(logline);
        return NULL;
    }

    return link;
}

static struct bpf_link *attach_uprobe_prog(struct bpf_object *obj, const char *prog_name, const char *binary_path, size_t func_offset, const char *desc, bool retprobe) __attribute__((unused));
static struct bpf_link *attach_uprobe_prog(struct bpf_object *obj, const char *prog_name, const char *binary_path, size_t func_offset, const char *desc, bool retprobe) {
    if (!obj || !prog_name || !binary_path) return NULL;
    struct bpf_program *prog = bpf_object__find_program_by_name(obj, prog_name);
    if (!prog) {
        const char *names[] = {prog_name};
        prog = find_bpf_program(obj, names, sizeof(names) / sizeof(names[0]));
    }
    if (!prog) {
        return NULL;
    }

    return attach_uprobe_prog_by_program(prog, binary_path, func_offset, desc, retprobe);
}

static int attach_bpf_socket_prog(struct bpf_object *obj, const char *iface) {
    const char *names[] = {"socket", "socket_filter", "matrix_socket_filter", "matrix_socket_prog", "socket_prog"};
    struct bpf_program *prog = find_bpf_program(obj, names, sizeof(names) / sizeof(names[0]));
    if (!prog) {
        fprintf(stderr, "[BPF] No socket program found\n");
        return -1;
    }

    int prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        fprintf(stderr, "[BPF] Failed to get socket program fd\n");
        return -1;
    }

    g_bpf_sock_fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (g_bpf_sock_fd < 0) {
        perror("socket");
        return -1;
    }

    if (iface && iface[0] && strcmp(iface, "none") != 0) {
        int ifindex = if_nametoindex(iface);
        if (ifindex == 0) {
            fprintf(stderr, "[BPF] Unknown interface '%s'\n", iface);
            close(g_bpf_sock_fd);
            g_bpf_sock_fd = -1;
            return -1;
        }
        struct sockaddr_ll sll = {0};
        sll.sll_family = AF_PACKET;
        sll.sll_protocol = htons(ETH_P_ALL);
        sll.sll_ifindex = ifindex;
        if (bind(g_bpf_sock_fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
            perror("bind");
            close(g_bpf_sock_fd);
            g_bpf_sock_fd = -1;
            return -1;
        }
    }

    if (setsockopt(g_bpf_sock_fd, SOL_SOCKET, SO_ATTACH_BPF, &prog_fd, sizeof(prog_fd)) != 0) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] SO_ATTACH_BPF failed on %s: %s", (iface && *iface) ? iface : "<any>", strerror(errno));
        perror("SO_ATTACH_BPF");
        push_log(logline);
        close(g_bpf_sock_fd);
        g_bpf_sock_fd = -1;
        return -1;
    }

    char logline[256];
    snprintf(logline, sizeof(logline), "[BPF] Socket filter attached on %s", (iface && *iface) ? iface : "<any>");
    printf("%s\n", logline);
    push_log(logline);
    return 0;
}

static int ringbuf_init(void) {
    if (g_ringbuf) return 0;

    char bpf_path_resolved[PATH_MAX];
    const char *bpf_path_env = getenv("NEXUS_BPF_OBJECT");
    if (!bpf_path_env || !*bpf_path_env) bpf_path_env = getenv("PEC_BPF_OBJECT");
    const char *bpf_path = bpf_path_env ? bpf_path_env : "ebpf/matrix_pipe.bpf.o";
    if (!resolve_bpf_object_path(bpf_path_resolved, sizeof(bpf_path_resolved), bpf_path)) {
        strncpy(bpf_path_resolved, bpf_path, sizeof(bpf_path_resolved) - 1);
        bpf_path_resolved[sizeof(bpf_path_resolved) - 1] = '\0';
    }
    const char *pin_path = getenv("NEXUS_BPF_RINGBUF_PIN");
    if (!pin_path || !*pin_path) pin_path = getenv("PEC_BPF_RINGBUF_PIN");
    if (!pin_path) pin_path = "/sys/fs/bpf/pec_ringbuf";

    char cwd[PATH_MAX] = {0};
    if (getcwd(cwd, sizeof(cwd))) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] cwd=%s, using BPF object %s", cwd, bpf_path_resolved);
        push_log(logline);
    }

    if (geteuid() != 0) {
        push_log("[BPF] Running without root privileges: BPF load may fail. Use sudo or root.");
    }

    struct rlimit rlim = {RLIM_INFINITY, RLIM_INFINITY};
    if (setrlimit(RLIMIT_MEMLOCK, &rlim) != 0) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] setrlimit(RLIMIT_MEMLOCK) failed: %s", strerror(errno));
        push_log(logline);
    }
    log_bpf_privileges();

    libbpf_set_strict_mode(LIBBPF_STRICT_NONE);
    push_log("[BPF] libbpf strict mode set to NONE before object open");

    if (access(bpf_path_resolved, R_OK) == 0) {
        errno = 0;
        g_bpf_obj = bpf_object__open_file(bpf_path_resolved, NULL);
        int open_err = errno ? errno : EIO;
        if (!g_bpf_obj) {
            char errbuf[256];
            const char *errstr = portable_strerror_r(open_err, errbuf, sizeof(errbuf));
            char logline[256];
            snprintf(logline, sizeof(logline), "[BPF] Failed to open object %s: %s", bpf_path_resolved, errstr);
            fprintf(stderr, "%s\n", logline);
            push_log(logline);
        } else {
            int load_err = bpf_object__load(g_bpf_obj);
            if (load_err) {
                int err = load_err < 0 ? -load_err : load_err;
                if (err <= 0) err = EPERM;
                char errbuf[256];
                const char *errstr = portable_strerror_r(err, errbuf, sizeof(errbuf));
                char logline[256];
                if (err == EPERM || err == EACCES) {
                    snprintf(logline, sizeof(logline), "[BPF] Failed to load object %s: %s (need root/CAP_BPF/CAP_SYS_ADMIN and RLIMIT_MEMLOCK)", bpf_path_resolved, errstr);
                } else {
                    snprintf(logline, sizeof(logline), "[BPF] Failed to load object %s: %s", bpf_path_resolved, errstr);
                }
                fprintf(stderr, "%s\n", logline);
                push_log(logline);
                log_bpf_privileges();
                bpf_object__close(g_bpf_obj);
                g_bpf_obj = NULL;
            } else {
                char logline[256];
                snprintf(logline, sizeof(logline), "[BPF] Loaded object %s", bpf_path_resolved);
                printf("%s\n", logline);
                push_log(logline);
                if (g_bpf_obj) {
                    log_bpf_programs(g_bpf_obj);  // Debug: list all available programs
                    apply_bpf_filter_config(g_bpf_obj);
                    attach_bpf_socket_prog(g_bpf_obj, g_bpf_iface);
                    attach_bpf_ssl_uprobes(g_bpf_obj);
                }
                g_ringbuf_fd = bpf_object__find_map_fd_by_name(g_bpf_obj, "events");
                if (g_ringbuf_fd < 0) {
                    char logline2[256];
                    snprintf(logline2, sizeof(logline2), "[BPF] Map 'events' not found in %s: %s", bpf_path_resolved, strerror(errno));
                    fprintf(stderr, "%s\n", logline2);
                    push_log(logline2);
                    bpf_object__close(g_bpf_obj);
                    g_bpf_obj = NULL;
                }
            }
        }
    } else {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] BPF object %s not readable: %s", bpf_path_resolved, strerror(errno));
        fprintf(stderr, "%s\n", logline);
        push_log(logline);
    }

    if (g_ringbuf_fd < 0) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] Trying pinned ringbuf %s", pin_path);
        push_log(logline);
        g_ringbuf_fd = ringbuf_open_pinned(pin_path);
        if (g_ringbuf_fd < 0) {
            snprintf(logline, sizeof(logline), "[BPF] Trying pinned ringbuf /sys/fs/bpf/god_mode_ringbuf");
            push_log(logline);
            g_ringbuf_fd = ringbuf_open_pinned("/sys/fs/bpf/god_mode_ringbuf");
        }
        if (g_ringbuf_fd < 0) {
            snprintf(logline, sizeof(logline), "[BPF] Trying pinned ringbuf /sys/fs/bpf/events");
            push_log(logline);
            g_ringbuf_fd = ringbuf_open_pinned("/sys/fs/bpf/events");
        }
    }

    if (g_ringbuf_fd < 0 && geteuid() == 0) {
        char logline[256];
        snprintf(logline, sizeof(logline), "[BPF] Creating local ringbuf map pec_ringbuf");
        push_log(logline);
        g_ringbuf_fd = bpf_map_create(BPF_MAP_TYPE_RINGBUF, "pec_ringbuf", 0, 0, 1 << 20, NULL);
        if (g_ringbuf_fd < 0) {
            fprintf(stderr, "[BPF] bpf_map_create failed: %s\n", strerror(errno));
            char logline2[256];
            snprintf(logline2, sizeof(logline2), "[BPF] bpf_map_create failed: %s", strerror(errno));
            push_log(logline2);
            return -1;
        }
    }

    if (g_ringbuf_fd < 0) {
        fprintf(stderr, "[BPF] Could not acquire ringbuf map; run as root or pin the map via pin path.\n");
        push_log("[BPF] Could not acquire ringbuf map; run as root or pin the map.");
        return -1;
    }

    g_ringbuf = ring_buffer__new(g_ringbuf_fd, ringbuf_event_handler, NULL, NULL);
    if (!g_ringbuf) {
        fprintf(stderr, "[BPF] ring_buffer__new failed\n");
        push_log("[BPF] ring_buffer__new failed");
        if (g_bpf_obj) bpf_object__close(g_bpf_obj);
        close(g_ringbuf_fd);
        g_ringbuf_fd = -1;
        g_bpf_obj = NULL;
        return -1;
    }

    char logline[256];
    snprintf(logline, sizeof(logline), "[BPF] RingBuf consumer attached on fd=%d", g_ringbuf_fd);
    printf("%s\n", logline);

    g_bpf_stats_fd = bpf_obj_get(BPF_STATS_MAP_PATH);
    if (g_bpf_stats_fd >= 0) {
        printf("[BPF] Stats map attached\n");
        push_log("[BPF] Stats map attached");
    }
    return 0;
}

static const uint8_t *bot_strip_websocket_headers(const uint8_t *data, size_t data_len, size_t *out_len, size_t *consumed) {
    if (!data || !out_len || !consumed) return data;
    *out_len = 0;
    *consumed = 0;
    if (data_len < 2) return data;

    static uint8_t stripped[MAX_PARSER_BUF];
    size_t pos = 0;
    size_t out = 0;

    while (pos + 2 <= data_len && out < sizeof(stripped)) {
        uint8_t b0 = data[pos];
        uint8_t b1 = data[pos + 1];
        uint8_t opcode = b0 & 0x0F;
        uint64_t payload_len = b1 & 0x7F;
        size_t header_len = 2;

        if (opcode != 0x1 && opcode != 0x2 && opcode != 0x0 && opcode != 0x9 && opcode != 0xA && opcode != 0x8) {
            break;
        }

        if (payload_len == 126) {
            if (pos + 4 > data_len) break;
            payload_len = ((uint64_t)data[pos + 2] << 8) | data[pos + 3];
            header_len += 2;
        } else if (payload_len == 127) {
            if (pos + 10 > data_len) break;
            payload_len = 0;
            for (int i = 0; i < 8; i++) {
                payload_len = (payload_len << 8) | data[pos + 2 + i];
            }
            header_len += 8;
        }

        if (b1 & 0x80) {
            header_len += 4;
        }
        if (pos + header_len > data_len) break;
        if (pos + header_len + payload_len > data_len) break;

        if (opcode == 0x1 || opcode == 0x2 || opcode == 0x0) {
            size_t copy_len = (size_t)payload_len;
            if (out + copy_len > sizeof(stripped)) {
                copy_len = sizeof(stripped) - out;
            }
            memcpy(stripped + out, data + pos + header_len, copy_len);
            out += copy_len;
        }

        pos += header_len + payload_len;
        if (opcode == 0x1 && (b0 & 0x80) == 0) {
            continue;
        }
    }

    if (out > 0) {
        *out_len = out;
        *consumed = pos;
        return stripped;
    }
    return data;
}

static int ringbuf_event_handler(void *ctx, void *data, size_t size) {
    (void)ctx;
    if (!data || size < sizeof(struct matrix_event)) return 0;
    struct matrix_event *evt = (struct matrix_event *)data;

    atomic_fetch_add(&g_tui.events_total, 1);
    if (evt->event_type == EVENT_TYPE_HEARTBEAT) {
        push_log("[BPF] HEARTBEAT event");
        return 0;
    }

    switch (evt->event_type) {
        case EVENT_TYPE_SSL_READ:
            atomic_fetch_add(&g_ssl_read_events, 1);
            break;
        case EVENT_TYPE_SSL_WRITE:
            atomic_fetch_add(&g_ssl_write_events, 1);
            break;
        case EVENT_TYPE_SSL_READ_EX:
            atomic_fetch_add(&g_ssl_read_ex_events, 1);
            break;
        case EVENT_TYPE_SSL_WRITE_EX:
            atomic_fetch_add(&g_ssl_write_ex_events, 1);
            break;
        case EVENT_TYPE_SSL_WRITE_EX2:
            atomic_fetch_add(&g_ssl_write_ex2_events, 1);
            break;
        case EVENT_TYPE_SSL_WRITE_EARLY:
            atomic_fetch_add(&g_ssl_write_early_events, 1);
            break;
        case EVENT_TYPE_SSL_READ_EARLY:
            atomic_fetch_add(&g_ssl_read_early_events, 1);
            break;
        case EVENT_TYPE_SYSCALL_SEND:
            atomic_fetch_add(&g_ssl_write_events, 1);
            break;
        default:
            break;
    }

    const char *event_type_desc = "NORMAL";
    switch (evt->event_type) {
        case EVENT_TYPE_SSL_READ: event_type_desc = "SSL_READ"; break;
        case EVENT_TYPE_SSL_WRITE: event_type_desc = "SSL_WRITE"; break;
        case EVENT_TYPE_SSL_READ_EX: event_type_desc = "SSL_READ_EX"; break;
        case EVENT_TYPE_SSL_WRITE_EX: event_type_desc = "SSL_WRITE_EX"; break;
        case EVENT_TYPE_SSL_WRITE_EX2: event_type_desc = "SSL_WRITE_EX2"; break;
        case EVENT_TYPE_SSL_WRITE_EARLY: event_type_desc = "SSL_WRITE_EARLY"; break;
        case EVENT_TYPE_SSL_READ_EARLY: event_type_desc = "SSL_READ_EARLY"; break;
        case EVENT_TYPE_SYSCALL_SEND: event_type_desc = "SYSCALL_SEND"; break;
        default: break;
    }
    const char *proto_desc = evt->proto_hint == 1 ? "http" : evt->proto_hint == 2 ? "tls" : evt->proto_hint == 3 ? "ws?" : "udp";
    char sample[128] = {0};
    size_t sample_len = evt->payload_len < sizeof(sample) - 1 ? evt->payload_len : sizeof(sample) - 1;
    for (size_t i = 0; i < sample_len; i++) {
        uint8_t c = evt->data[i];
        sample[i] = isprint(c) ? (char)c : '.';
    }
    char event_log[256];
    snprintf(event_log, sizeof(event_log), "[BPF] EVENT type=%s len=%u proto=%s data=%s",
             event_type_desc, evt->payload_len, proto_desc, sample);
    push_log(event_log);
    update_last_event(event_log);

    const uint8_t *event_payload = evt->data;
    size_t event_len = evt->payload_len;
    if (event_len == 0) return 0;

    size_t ws_payload_len = 0;
    size_t ws_consumed = 0;
    const uint8_t *ws_payload = bot_strip_websocket_headers(event_payload, event_len, &ws_payload_len, &ws_consumed);

    const uint8_t *parse_body = ws_payload_len > 0 ? ws_payload : event_payload;
    size_t parse_len = ws_payload_len > 0 ? ws_payload_len : event_len;

    if (ws_payload_len > 0 && ws_payload_len != evt->payload_len) {
        char reasm_log[192];
        snprintf(reasm_log, sizeof(reasm_log), "[BPF] WS CLEANED payload len=%zu from raw len=%u",
                 ws_payload_len, evt->payload_len);
        push_log(reasm_log);
    }

    static struct matrix_event assembled_evt;
    assembled_evt = *evt;
    size_t copy_len = parse_len;
    if (copy_len > sizeof(assembled_evt.data)) {
        copy_len = sizeof(assembled_evt.data);
    }
    if (copy_len > 0) {
        memcpy(assembled_evt.data, parse_body, copy_len);
    }
    assembled_evt.payload_len = (uint32_t)copy_len;
    const struct matrix_event *event_for_parse = &assembled_evt;
    const uint8_t *body = parse_body;
    size_t body_len = parse_len;

    if (bot_contains_bybit_keyword(event_for_parse)) {
        char keyword_log[192];
        snprintf(keyword_log, sizeof(keyword_log), "[BPF] BYBIT KEYWORD match len=%u proto=%s",
                 event_for_parse->payload_len, proto_desc);
        update_last_event(keyword_log);
        push_log(keyword_log);

        if (body && body_len > 0) {
            char bybit_body_sample[192] = {0};
            size_t sample_len = body_len < sizeof(bybit_body_sample) - 1 ? body_len : sizeof(bybit_body_sample) - 1;
            for (size_t i = 0; i < sample_len; i++) {
                uint8_t c = body[i];
                bybit_body_sample[i] = isprint(c) ? (char)c : '.';
            }
            char bybit_body_log[256];
            snprintf(bybit_body_log, sizeof(bybit_body_log), "[BPF] BYBIT PAYLOAD sample=%s", bybit_body_sample);
            update_last_event(bybit_body_log);
            push_log(bybit_body_log);

            double ret_code = 0.0;
            char ret_msg[128] = {0};
            if (bot_extract_json_number(body, body_len, "\"retCode\"", &ret_code)) {
                char code_log[256];
                snprintf(code_log, sizeof(code_log), "[BPF] BYBIT RETCODE %.0f", ret_code);
                push_log(code_log);
                update_last_event(code_log);
            }
            if (bot_extract_json_string(body, body_len, "\"retMsg\"", ret_msg, sizeof(ret_msg))) {
                char msg_log[256];
                snprintf(msg_log, sizeof(msg_log), "[BPF] BYBIT RETMSG %s", ret_msg);
                push_log(msg_log);
                update_last_event(msg_log);
            }

            if (payload_contains_ci(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"orderbook.1.SOLUSDT", 19)) {
                double parsed_bid_price = 0.0, parsed_bid_qty = 0.0;
                double parsed_ask_price = 0.0, parsed_ask_qty = 0.0;
                if (bot_extract_bybit_ws_price_qty(event_for_parse->data, event_for_parse->payload_len, "\"b\":[[", &parsed_bid_price, &parsed_bid_qty)) {
                    if (parsed_bid_price > 0.0 && parsed_bid_qty > 0.0) {
                        atomic_store_float64(&g_solusdt_best_bid_price_bits, parsed_bid_price);
                        atomic_store_float64(&g_solusdt_best_bid_qty_bits, parsed_bid_qty);
                        char bid_log[192];
                        snprintf(bid_log, sizeof(bid_log), "[BPF] SOLUSDT BID UPDATE %.5f x %.5f", parsed_bid_price, parsed_bid_qty);
                        push_log(bid_log);
                        update_last_event(bid_log);
                    }
                }
                if (bot_extract_bybit_ws_price_qty(event_for_parse->data, event_for_parse->payload_len, "\"a\":[[", &parsed_ask_price, &parsed_ask_qty)) {
                    if (parsed_ask_price > 0.0 && parsed_ask_qty > 0.0) {
                        atomic_store_float64(&g_solusdt_best_ask_price_bits, parsed_ask_price);
                        atomic_store_float64(&g_solusdt_best_ask_qty_bits, parsed_ask_qty);
                        char ask_log[192];
                        snprintf(ask_log, sizeof(ask_log), "[BPF] SOLUSDT ASK UPDATE %.5f x %.5f", parsed_ask_price, parsed_ask_qty);
                        push_log(ask_log);
                        update_last_event(ask_log);
                    }
                }
            }

            char symbol[32] = {0};
            bot_extract_json_symbol(event_for_parse, symbol, sizeof(symbol));
            bool is_solusdt = bot_is_solusdt_symbol(symbol);
            const uint8_t *orderbook_src = parse_body && parse_len > 0 ? parse_body : event_for_parse->data;
            size_t orderbook_src_len = parse_body && parse_len > 0 ? parse_len : event_for_parse->payload_len;
            double sol_bid_price = 0.0, sol_bid_qty = 0.0, sol_ask_price = 0.0, sol_ask_qty = 0.0;
            if ((is_solusdt || payload_contains_ci(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"orderbook", 9) ||
                 payload_contains_ci(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"asks", 4) ||
                 payload_contains_ci(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"bids", 4)) &&
                bot_extract_orderbook_levels_for_symbol(orderbook_src, orderbook_src_len,
                                                       symbol, &sol_bid_price, &sol_bid_qty,
                                                       &sol_ask_price, &sol_ask_qty)) {
                if (is_solusdt) {
                    if (sol_bid_price > 0.0 && sol_bid_qty > 0.0) {
                        atomic_store_float64(&g_solusdt_best_bid_price_bits, sol_bid_price);
                        atomic_store_float64(&g_solusdt_best_bid_qty_bits, sol_bid_qty);
                    }
                    if (sol_ask_price > 0.0 && sol_ask_qty > 0.0) {
                        atomic_store_float64(&g_solusdt_best_ask_price_bits, sol_ask_price);
                        atomic_store_float64(&g_solusdt_best_ask_qty_bits, sol_ask_qty);
                    }
                    if (sol_bid_price > 0.0 && sol_ask_price > 0.0) {
                        double sol_mid = (sol_bid_price + sol_ask_price) * 0.5;
                        uint64_t sol_mid_bits;
                        memcpy(&sol_mid_bits, &sol_mid, sizeof(sol_mid_bits));
                        atomic_store(&g_last_sol_spot_price, sol_mid_bits);
                    }
                } else if (bot_is_sol_perp_symbol(symbol)) {
                    if (sol_bid_price > 0.0 && sol_ask_price > 0.0) {
                        double perp_mid = (sol_bid_price + sol_ask_price) * 0.5;
                        uint64_t perp_mid_bits;
                        memcpy(&perp_mid_bits, &perp_mid, sizeof(perp_mid_bits));
                        atomic_store(&g_last_sol_perp_price, perp_mid_bits);
                    }
                }
                char sol_depth_log[256];
                if (symbol[0]) {
                    snprintf(sol_depth_log, sizeof(sol_depth_log),
                             "[BPF] SOLUSDT ORDERBOOK %s bid=%.5f x %.5f ask=%.5f x %.5f",
                             symbol, sol_bid_price, sol_bid_qty, sol_ask_price, sol_ask_qty);
                } else {
                    snprintf(sol_depth_log, sizeof(sol_depth_log),
                             "[BPF] SOLUSDT ORDERBOOK bid=%.5f x %.5f ask=%.5f x %.5f",
                             sol_bid_price, sol_bid_qty, sol_ask_price, sol_ask_qty);
                }
                push_log(sol_depth_log);
                update_last_event(sol_depth_log);
            }
        }
    }

    if (payload_contains(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"\"asks\"", 6) ||
        payload_contains(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"\"bids\"", 6) ||
        payload_contains(event_for_parse->data, event_for_parse->payload_len, (uint8_t *)"\"symbol\"", 8)) {
        char json_log[192];
        snprintf(json_log, sizeof(json_log), "[BPF] BYBIT JSON payload len=%u proto=%s",
                 event_for_parse->payload_len, proto_desc);
        update_last_event(json_log);
        push_log(json_log);
    }

    bot_handle_event(event_for_parse);

    float tmp_matrix[PHASE_DIM * PHASE_DIM] = {0};
    if (!za_tensor_collapse(tmp_matrix, evt, PHASE_DIM)) {
        atomic_fetch_add(&g_tui.partial_invalid, 1);
        return 0;
    }
    float peak = resonance_peak(tmp_matrix, PHASE_DIM);
    atomic_store(&g_peak_resonance, peak);

    uint64_t latency_ns = get_time_ns();
    if (evt->timestamp) {
        uint64_t delta = (latency_ns > evt->timestamp) ? (latency_ns - evt->timestamp) : 0;
        atomic_store(&g_tui.e2e_latency_last_ns, delta);
        atomic_fetch_add(&g_tui.e2e_latency_total_ns, delta);
        atomic_fetch_add(&g_tui.e2e_latency_count, 1);
    }

    if (peak > COLLAPSE_THRESH) {
        atomic_fetch_add(&g_total_collapses, 1);
    }
    if (g_raw_stream_log || peak > COLLAPSE_THRESH) {
        char logline[192];
        snprintf(logline, sizeof(logline), "TICK %s:%u→%s:%u [%s] peak=%.3f len=%u",
                 inet_ntoa((struct in_addr){.s_addr=evt->src_ip}), ntohs(evt->src_port),
                 inet_ntoa((struct in_addr){.s_addr=evt->dst_ip}), ntohs(evt->dst_port),
                 proto_desc, peak, evt->payload_len);
        push_log(logline);
    }
    return 0;
}

static void *ringbuf_worker(void *arg) {
    (void)arg;
    pin_current_thread(0);
    while (atomic_load(&g_running) && g_ringbuf) {
        int ret = ring_buffer__poll(g_ringbuf, g_ringbuf_poll_ms);
        if (ret < 0) break;
    }
    return NULL;
}

static void *pec_worker(void *arg) {
    uint32_t thread_idx = (uintptr_t)arg;
    uint32_t cores = sysconf(_SC_NPROCESSORS_ONLN);
    uint32_t per = PEC_VIRTUAL_CHANNELS / g_worker_threads;
    uint32_t start = thread_idx * per;
    uint32_t end = (thread_idx == g_worker_threads - 1) ? PEC_VIRTUAL_CHANNELS : start + per;
    if (end > PEC_VIRTUAL_CHANNELS) end = PEC_VIRTUAL_CHANNELS;

    cpu_set_t cpuset; CPU_ZERO(&cpuset);
    CPU_SET(thread_idx % cores, &cpuset);
    pthread_setaffinity_np(pthread_self(), sizeof(cpu_set_t), &cpuset);
    usleep(THREAD_PIN_DELAY_US);
    
    while (atomic_load(&g_running)) {
        for (uint32_t i = start; i < end; i++) {
            if (channel_process(&g_channels[i], COLLAPSE_THRESH)) {
                ipc_signal_collapse(g_channels[i].collapses, g_channels[i].last_coherence);
            }
        }
        uint32_t sleep_ms = g_pec_sleep_min_ms + (rand() % (g_pec_sleep_max_ms - g_pec_sleep_min_ms + 1));
        struct timespec ts = { .tv_sec = 0, .tv_nsec = (sleep_ms) * 1000000L };
        nanosleep(&ts, NULL);
    }
    return NULL;
}

/* ============================================================================
   TUI WORKER (C-compatible thread function)
============================================================================ */
static void *tui_worker(void *arg) {
    (void)arg;
    struct timespec t_last; clock_gettime(CLOCK_MONOTONIC_RAW, &t_last);
    while (atomic_load(&g_tui.running)) {
        render_tui();
        uint64_t c, i, m;
        perf_update(&g_perf, &c, &i, &m);
        atomic_store(&g_tui.cycles_delta, c);
        atomic_store(&g_tui.inst_delta, i);
        atomic_store(&g_tui.cache_miss_delta, m);
        struct timespec now; clock_gettime(CLOCK_MONOTONIC_RAW, &now);
        if (now.tv_sec - t_last.tv_sec >= 1) { t_last = now; }
        usleep(g_tui_update_ms * 1000);
    }
    return NULL;
}

/* ============================================================================
   MAIN
============================================================================ */
static volatile bool sig_quit = false;
static void sig_handler(int s) { (void)s; atomic_store(&g_running, false); sig_quit = true; }

int main(int argc, char **argv) {
    signal(SIGINT, sig_handler); signal(SIGTERM, sig_handler);
    
    const char *backend_override = NULL;
    const char *iface_override = NULL;
    const char *mode_override = NULL;
    const char *bot_key_override = NULL;
    const char *bot_secret_override = NULL;
    const char *copy_wallet_override = NULL;
    const char *contract_override = NULL;
    const char *event_sig_override = NULL;
    const char *max_price_override = NULL;
    const char *min_liquidity_override = NULL;
    const char *delta_pct_override = NULL;
    const char *imbalance_override = NULL;
    const char *exit_imbalance_override = NULL;
    const char *latency_spike_override = NULL;
    const char *max_latency_override = NULL;
    const char *cooldown_override = NULL;
    const char *slippage_override = NULL;
    const char *tp_override = NULL;
    const char *sl_override = NULL;
    const char *presigned_tx_override = NULL;
    bool sniper_enable_override = false;
    bool anti_rug_override = false;
    bool mev_protect_override = false;
    bool copy_trade_override = false;
    bool auto_snipe_override = false;
    bool keepalive_override = false;
    bool keepalive_disable_override = false;
    bool warmup_disable_override = false;

    for (int i = 1; i < argc; i++) {
        if (strncmp(argv[i], "--target=", 9) == 0) parse_target(argv[i] + 9, &g_target);
        else if (strcmp(argv[i], "--target") == 0 && i+1 < argc) parse_target(argv[++i], &g_target);
        else if (strncmp(argv[i], "--backend=", 10) == 0) backend_override = argv[i] + 10;
        else if (strcmp(argv[i], "--backend") == 0 && i+1 < argc) backend_override = argv[++i];
        else if (strncmp(argv[i], "--iface=", 8) == 0) iface_override = argv[i] + 8;
        else if (strcmp(argv[i], "--iface") == 0 && i+1 < argc) iface_override = argv[++i];
        else if (strncmp(argv[i], "--mode=", 7) == 0) mode_override = argv[i] + 7;
        else if (strcmp(argv[i], "--mode") == 0 && i+1 < argc) mode_override = argv[++i];
        else if (strncmp(argv[i], "--key=", 6) == 0) bot_key_override = argv[i] + 6;
        else if (strcmp(argv[i], "--key") == 0 && i+1 < argc) bot_key_override = argv[++i];
        else if (strncmp(argv[i], "--secret=", 9) == 0) bot_secret_override = argv[i] + 9;
        else if (strcmp(argv[i], "--secret") == 0 && i+1 < argc) bot_secret_override = argv[++i];
        else if (strncmp(argv[i], "--copy-wallet=", 14) == 0) copy_wallet_override = argv[i] + 14;
        else if (strcmp(argv[i], "--copy-wallet") == 0 && i+1 < argc) copy_wallet_override = argv[++i];
        else if (strncmp(argv[i], "--contract=", 11) == 0) contract_override = argv[i] + 11;
        else if (strcmp(argv[i], "--contract") == 0 && i+1 < argc) contract_override = argv[++i];
        else if (strncmp(argv[i], "--event-sig=", 12) == 0) event_sig_override = argv[i] + 12;
        else if (strcmp(argv[i], "--event-sig") == 0 && i+1 < argc) event_sig_override = argv[++i];
        else if (strncmp(argv[i], "--max-price=", 12) == 0) max_price_override = argv[i] + 12;
        else if (strcmp(argv[i], "--max-price") == 0 && i+1 < argc) max_price_override = argv[++i];
        else if (strncmp(argv[i], "--min-liquidity=", 16) == 0) min_liquidity_override = argv[i] + 16;
        else if (strcmp(argv[i], "--min-liquidity") == 0 && i+1 < argc) min_liquidity_override = argv[++i];
        else if (strncmp(argv[i], "--presigned-tx=", 14) == 0) presigned_tx_override = argv[i] + 14;
        else if (strcmp(argv[i], "--presigned-tx") == 0 && i+1 < argc) presigned_tx_override = argv[++i];
        else if (strcmp(argv[i], "--keepalive") == 0) keepalive_override = true;
        else if (strcmp(argv[i], "--no-keepalive") == 0) keepalive_disable_override = true;
        else if (strncmp(argv[i], "--delta-pct=", 11) == 0) delta_pct_override = argv[i] + 11;
        else if (strcmp(argv[i], "--delta-pct") == 0 && i+1 < argc) delta_pct_override = argv[++i];
        else if (strncmp(argv[i], "--imbalance-ratio=", 17) == 0) imbalance_override = argv[i] + 17;
        else if (strcmp(argv[i], "--imbalance-ratio") == 0 && i+1 < argc) imbalance_override = argv[++i];
        else if (strncmp(argv[i], "--exit-imbalance-ratio=", 23) == 0) exit_imbalance_override = argv[i] + 23;
        else if (strcmp(argv[i], "--exit-imbalance-ratio") == 0 && i+1 < argc) exit_imbalance_override = argv[++i];
        else if (strncmp(argv[i], "--latency-spike-ms=", 19) == 0) latency_spike_override = argv[i] + 19;
        else if (strcmp(argv[i], "--latency-spike-ms") == 0 && i+1 < argc) latency_spike_override = argv[++i];
        else if (strncmp(argv[i], "--max-latency=", 14) == 0) max_latency_override = argv[i] + 14;
        else if (strcmp(argv[i], "--max-latency") == 0 && i+1 < argc) max_latency_override = argv[++i];
        else if (strncmp(argv[i], "--cooldown=", 11) == 0) cooldown_override = argv[i] + 11;
        else if (strcmp(argv[i], "--cooldown") == 0 && i+1 < argc) cooldown_override = argv[++i];
        else if (strncmp(argv[i], "--slippage=", 11) == 0) slippage_override = argv[i] + 11;
        else if (strcmp(argv[i], "--slippage") == 0 && i+1 < argc) slippage_override = argv[++i];
        else if (strncmp(argv[i], "--tp-pct=", 8) == 0) tp_override = argv[i] + 8;
        else if (strcmp(argv[i], "--tp-pct") == 0 && i+1 < argc) tp_override = argv[++i];
        else if (strncmp(argv[i], "--sl-pct=", 8) == 0) sl_override = argv[i] + 8;
        else if (strcmp(argv[i], "--sl-pct") == 0 && i+1 < argc) sl_override = argv[++i];
        else if (strcmp(argv[i], "--no-warmup") == 0) warmup_disable_override = true;
        else if (strcmp(argv[i], "--sniper") == 0 || strcmp(argv[i], "--snipe") == 0) sniper_enable_override = true;
        else if (strcmp(argv[i], "--anti-rug") == 0) anti_rug_override = true;
        else if (strcmp(argv[i], "--mev-protection") == 0) mev_protect_override = true;
        else if (strcmp(argv[i], "--copy-trade") == 0) copy_trade_override = true;
        else if (strcmp(argv[i], "--auto-snipe") == 0) auto_snipe_override = true;
        else if (strcmp(argv[i], "--direct-splice") == 0) atomic_store(&g_bot_direct_splice, true);
        else if (strcmp(argv[i], "--wormhole") == 0) atomic_store(&g_bot_wormhole, true);
        else if (strcmp(argv[i], "--x11-stealth") == 0) atomic_store(&g_bot_x11_stealth, true);
    }

    if (bot_key_override) strncpy(g_bot_api_key, bot_key_override, sizeof(g_bot_api_key) - 1);
    if (bot_secret_override) strncpy(g_bot_api_secret, bot_secret_override, sizeof(g_bot_api_secret) - 1);
    if (copy_wallet_override) strncpy(g_copy_wallet, copy_wallet_override, sizeof(g_copy_wallet) - 1);
    if (contract_override) parse_pattern_arg(contract_override, (uint8_t *)g_bot_target_contract, &g_bot_target_contract_len, sizeof(g_bot_target_contract));
    if (event_sig_override) parse_pattern_arg(event_sig_override, (uint8_t *)g_bot_event_signature, &g_bot_event_signature_len, sizeof(g_bot_event_signature));
    if (max_price_override) g_bybit_max_price_usdt = strtof(max_price_override, NULL);
    if (min_liquidity_override) g_bybit_min_liquidity = strtof(min_liquidity_override, NULL);
    if (delta_pct_override) g_bybit_price_delta_pct = strtof(delta_pct_override, NULL);
    if (imbalance_override) g_bybit_imbalance_ratio = strtof(imbalance_override, NULL);
    if (exit_imbalance_override) g_bybit_exit_imbalance_ratio = strtof(exit_imbalance_override, NULL);
    if (latency_spike_override) g_bybit_internal_latency_spike_ms = strtof(latency_spike_override, NULL);
    if (max_latency_override) g_bybit_latency_tolerance_ms = strtof(max_latency_override, NULL);
    if (cooldown_override) g_bot_trade_cooldown_ns = (uint64_t)strtoul(cooldown_override, NULL, 10) * 1000000000ULL;
    if (slippage_override) g_bot_slippage_pct = strtof(slippage_override, NULL);
    if (tp_override) g_bot_take_profit_pct = strtof(tp_override, NULL);
    if (sl_override) g_bot_stop_loss_pct = strtof(sl_override, NULL);
    if (presigned_tx_override) strncpy(g_bybit_presigned_tx, presigned_tx_override, sizeof(g_bybit_presigned_tx) - 1);
    if (keepalive_override) atomic_store(&g_bybit_keepalive, true);
    if (keepalive_disable_override) atomic_store(&g_bybit_keepalive, false);
    if (warmup_disable_override) atomic_store(&g_amx_warmup_enabled, false);
    if (sniper_enable_override) atomic_store(&g_sniper_bot_enabled, true);
    if (anti_rug_override) atomic_store(&g_anti_rug_enabled, true);
    if (mev_protect_override) atomic_store(&g_mev_protection_enabled, true);
    if (copy_trade_override) atomic_store(&g_copy_trading_enabled, true);
    if (auto_snipe_override) atomic_store(&g_auto_snipe_enabled, true);

    if (backend_override) {
        if (!parse_backend_arg(backend_override, &g_backend)) {
            fprintf(stderr, "[ERROR] Invalid backend '%s'. Use amx|neon|scalar\n", backend_override);
            return 1;
        }
    } else {
        g_backend = detect_backend();
    }

    if (iface_override && *iface_override) g_bpf_iface = iface_override;
    if (mode_override && *mode_override) {
        if (is_valid_bpf_mode(mode_override)) g_bpf_mode = mode_override;
        else fprintf(stderr, "[WARN] Invalid BPF mode '%s'; using %s\n", mode_override, g_bpf_mode);
    }
    
    g_sq_poll_cpu = select_sq_cpu();
    
    printf("=== PEC Matrix Engine v1.9.2 | Target: %s (%s):%u | Iface: %s | Mode: %s ===\n", 
           g_target.hostname, g_target.host, g_target.port, g_bpf_iface[0] ? g_bpf_iface : "<any>", g_bpf_mode);
    printf("[BACKEND] %s | SQPOLL CPU: %d\n", 
           g_backend == BACKEND_SME2 ? "SME2" : g_backend == BACKEND_AMX ? "AMX" : g_backend == BACKEND_NEON ? "NEON" : "SCALAR",
           g_sq_poll_cpu);
    
    for (uint32_t i = 0; i < PEC_VIRTUAL_CHANNELS; i++) channel_init(&g_channels[i], (uint64_t)i * 2654435761ULL);
    
    configure_defaults();
    bot_init();
    perf_init(&g_perf);
    
    if (g_backend == BACKEND_SME2) {
        sme2_keep_alive();
        printf("[SME2] Streaming mode enabled\n");
    }
    if (ipc_init() == 0) printf("[IPC] SHM + eventfd ready\n");
    if (ringbuf_init() == 0) printf("[BPF] RingBuf consumer ready\n");
    else printf("[BPF] RingBuf consumer failed\n");
    
    uint32_t cores = sysconf(_SC_NPROCESSORS_ONLN);
    if (g_worker_threads > cores) g_worker_threads = cores;
    pthread_t threads[g_worker_threads];
    for (uint32_t i = 0; i < g_worker_threads; i++) pthread_create(&threads[i], NULL, pec_worker, (void *)(uintptr_t)i);
    
    pthread_t ringbuf_thread;
    bool ringbuf_thread_started = false;
    if (g_ringbuf && pthread_create(&ringbuf_thread, NULL, ringbuf_worker, NULL) == 0) {
        ringbuf_thread_started = true;
        printf("[BPF] RingBuf thread started\n");
    }

    pthread_t warmup_thread;
    bool warmup_thread_started = false;
    if (atomic_load(&g_amx_warmup_enabled)) {
        if (pthread_create(&warmup_thread, NULL, amx_warmup_worker, NULL) == 0) {
            printf("[AMX] Warm-up thread started\n");
            warmup_thread_started = true;
        } else {
            fprintf(stderr, "[AMX] Warm-up thread failed to start\n");
        }
    }

    pthread_t traffic_thread;
    bool traffic_thread_started = false;
    if (g_target.is_https) {
        if (pthread_create(&traffic_thread, NULL, bot_traffic_worker, NULL) == 0) {
            printf("[BOT] Traffic warmup thread started\n");
            traffic_thread_started = true;
        } else {
            fprintf(stderr, "[BOT] Traffic warmup thread failed to start\n");
        }
    }
    
    pthread_t tui_tid;
    atomic_store(&g_tui.running, true);
    pthread_create(&tui_tid, NULL, tui_worker, NULL);
    
    printf("[STARTED] Press Ctrl+C to stop.\n");
    while (!sig_quit) {
        usleep(10000);
    }
    
    printf("\n[SHUTDOWN] Cleaning...\n");
    atomic_store(&g_tui.running, false);
    pthread_join(tui_tid, NULL);
    if (traffic_thread_started) pthread_join(traffic_thread, NULL);
    if (warmup_thread_started) pthread_join(warmup_thread, NULL);
    for (uint32_t i = 0; i < g_worker_threads; i++) pthread_join(threads[i], NULL);
    if (ringbuf_thread_started) pthread_join(ringbuf_thread, NULL);
    if (g_ringbuf) ring_buffer__free(g_ringbuf);
    if (g_ringbuf_fd >= 0) close(g_ringbuf_fd);
    if (g_bpf_sock_fd >= 0) close(g_bpf_sock_fd);
    if (g_bpf_ssl_read_entry_link) bpf_link__destroy(g_bpf_ssl_read_entry_link);
    if (g_bpf_ssl_write_entry_link) bpf_link__destroy(g_bpf_ssl_write_entry_link);
    if (g_bpf_ssl_read_link) bpf_link__destroy(g_bpf_ssl_read_link);
    if (g_bpf_ssl_write_link) bpf_link__destroy(g_bpf_ssl_write_link);
    if (g_bpf_ssl_read_ex_link) bpf_link__destroy(g_bpf_ssl_read_ex_link);
    if (g_bpf_ssl_write_ex_link) bpf_link__destroy(g_bpf_ssl_write_ex_link);
    if (g_bpf_obj) bpf_object__close(g_bpf_obj);
    bot_tls_cleanup();
    if (g_backend == BACKEND_SME2) sme2_shutdown();
    if (g_shm) munmap(g_shm, SHM_SIZE);
    if (g_shm_fd >= 0) { close(g_shm_fd); shm_unlink(SHM_NAME); }
    if (g_eventfd >= 0) close(g_eventfd);
    if (g_perf.fd_cycles >= 0) close(g_perf.fd_cycles);
    if (g_perf.fd_instr >= 0) close(g_perf.fd_instr);
    if (g_perf.fd_cache >= 0) close(g_perf.fd_cache);

    if (g_tui.header_printed) {
        printf("\033[?25h\033[?1049l");
        fflush(stdout);
    }
    printf("[DONE] Collapses: %"PRIu64"\n", atomic_load(&g_total_collapses));
    return 0;
}
