#!/bin/bash
set -e

cd "$(dirname "$0")"

echo "[NEXUS] AMX Pipeline v4.0 — Kali ARM64"
echo "[1/3] Checking environment..."

# Проверка root для eBPF/XDP
if [ "$EUID" -ne 0 ]; then
    echo "[WARN] eBPF/XDP требует root. Запустите: sudo ./run.sh ..."
fi

# Проверка зависимостей (мягкая)
for pkg in clang g++ bpftool libbpf-dev liburing-dev; do
    if ! dpkg -l "$pkg" &>/dev/null && ! command -v "${pkg%-dev}" &>/dev/null; then
        echo "[INFO] $pkg может отсутствовать. Запустите: sudo make install-deps"
    fi
done

# Сборка
echo "[2/3] Building..."
make clean >/dev/null 2>&1 || true
if ! make ebpf userspace 2>&1; then
    echo "[ERR] Build failed. Проверьте: linux-headers-$(uname -r) установлен?"
    exit 1
fi

echo "[3/3] Запуск..."
echo "[✓] Binary: ./nexus_amx_pipeline"
echo "[✓] Usage: sudo ./nexus_amx_pipeline --target http://HOST:PORT --iface eth0"
echo ""

# Передача аргументов в бинарник
./nexus_amx_pipeline "$@"