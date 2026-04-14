#!/bin/bash
echo "[*] building eBPF..."
echo "clang netmon_kern.c -o netmon_kern.o"

echo "[*] packaging..."
zip -r NetMonitor-Pro-Full.zip .

echo "[+] done"
