# Auto-detect available clang version
CLANG_VERSIONS := clang-18 clang-17 clang-16 clang-14 clang
CLANG := $(firstword $(foreach v,$(CLANG_VERSIONS),$(if $(shell command -v $(v) 2>/dev/null),$(v))))
ifeq ($(CLANG),)
$(error "clang not found. Install: sudo apt install clang")
endif

CC_VERSIONS := gcc-14 gcc-13 gcc-12 gcc
CC := $(firstword $(foreach v,$(CC_VERSIONS),$(if $(shell command -v $(v) 2>/dev/null),$(v))))
ifeq ($(CC),)
$(error "gcc not found. Install: sudo apt install gcc")
endif

CXX_VERSIONS := g++-13 g++-12 g++-11 g++
CXX := $(firstword $(foreach v,$(CXX_VERSIONS),$(if $(shell command -v $(v) 2>/dev/null),$(v))))
ifeq ($(CXX),)
$(error "g++ not found. Install: sudo apt install g++")
endif

BPFTOOL := $(shell command -v bpftool 2>/dev/null)
ifeq ($(BPFTOOL),)
$(error "bpftool not found. Install: sudo apt install bpftool")
endif

# Auto-detect kernel headers
KERNEL_RELEASE := $(shell uname -r)
KHEADER_PATH := /usr/include/$(KERNEL_RELEASE)/build/tools/lib/bpf/
ifeq ($(wildcard $(KHEADER_PATH)),)
# Fallback: generic path
KHEADER_PATH := /usr/include/linux/bpf/
endif

CFLAGS  := -std=c++20 -O3 -DUSE_AMX -march=armv8-a -fno-rtti -Wall -Wextra -pthread -ffast-math
LDFLAGS := -luring -lbpf -lpthread -lrt -lm

EBPF_DIR := ebpf
SRC      := matrix_amx_pipeline.cpp
OUT      := nexus_amx_pipeline
ORDER_SIGNER_SRC := nexus_order_signer.cpp
ORDER_SIGNER_OUT := nexus_order_signer
PEC_SRC := pec_matrix_engine.c
PEC_OUT := pec_matrix_engine

.PHONY: all ebpf userspace order_signer pec_matrix_engine clean install-deps

all: ebpf userspace order_signer pec_matrix_engine

ebpf:
	@echo "[BUILD] Compiling eBPF with $(CLANG)..."
	$(CLANG) -g -O2 -fno-unroll-loops -target bpf -D__TARGET_ARCH_arm64 -Dbpf_target_arm64 \
		-I/usr/include \
		-I/usr/include/aarch64-linux-gnu \
		-I$(KHEADER_PATH) \
		-I/usr/src/linux-headers-$(KERNEL_RELEASE)/include \
		-I/usr/src/linux-headers-$(KERNEL_RELEASE)/arch/arm64/include/generated \
		-c $(EBPF_DIR)/matrix_pipe.bpf.c -o $(EBPF_DIR)/matrix_pipe.bpf.o

userspace:
	@echo "[BUILD] Compiling userspace with $(CXX)..."
	$(CXX) $(CFLAGS) $(SRC) -o $(OUT) $(LDFLAGS)

order_signer:
	@echo "[BUILD] Compiling order signer with $(CXX)..."
	$(CXX) $(CFLAGS) $(ORDER_SIGNER_SRC) -o $(ORDER_SIGNER_OUT) -lpthread -lrt -lm

pec_matrix_engine: ebpf
	@echo "[BUILD] Compiling pec_matrix_engine with $(CC)..."
	$(CC) -std=c11 -O3 -march=armv8-a -Wall -Wextra -pthread -ffast-math $(PEC_SRC) -o $(PEC_OUT) $(LDFLAGS) -lssl -lcrypto

clean:
	rm -f $(EBPF_DIR)/matrix_pipe.bpf.o $(OUT) nexus_amx.log

install-deps:
	@echo "[DEPS] Installing dependencies for Kali ARM64..."
	@apt-get update -qq
	@apt-get install -y -qq \
		clang \
		g++ \
		bpftool \
		libbpf-dev \
		liburing-dev \
		linux-headers-$(KERNEL_RELEASE) \
		2>/dev/null || \
	apt-get install -y -qq \
		clang \
		g++ \
		bpftool \
		libbpf-dev \
		liburing-dev \
		linux-headers-arm64 \
		2>/dev/null || \
	(echo "[WARN] Some packages may need manual install" && exit 0)