# NetMonitor Pro — eBPF 编译 Makefile (优化版)
# 文件位置: ebpf/Makefile
#
# 优化点:
#   1. 自动检测内核头文件路径
#   2. 增加 vmlinux.h 生成目标
#   3. 增加 install / uninstall 目标
#   4. 增加 format / check 代码质量目标

CLANG      ?= clang
LLC        ?= llc
BPFTOOL    ?= bpftool
STRIP      ?= llvm-strip

ARCH       := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_SRC   := netmon_kern.c
KERN_OBJ   := netmon_kern.o
VMLINUX_H  := vmlinux.h

# 内核头文件路径自动检测
KERNEL_VERSION := $(shell uname -r)
KERNEL_HEADERS := /lib/modules/$(KERNEL_VERSION)/build

# 编译选项
CFLAGS := -O2 -g -Wall -Werror \
          -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I. \
          -I$(KERNEL_HEADERS)/include

.PHONY: all clean install uninstall vmlinux format check help

all: $(KERN_OBJ)

# 生成 vmlinux.h（如果不存在）
$(VMLINUX_H):
	@echo "[*] 生成 vmlinux.h ..."
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > $@
	@echo "[✓] vmlinux.h 已生成"

# 编译 eBPF 内核程序
$(KERN_OBJ): $(KERN_SRC) $(VMLINUX_H)
	@echo "[*] 编译 eBPF 内核探针 ..."
	$(CLANG) $(CFLAGS) -c $(KERN_SRC) -o $@
	@$(STRIP) -g $@ 2>/dev/null || true
	@echo "[✓] 编译完成: $@"

# 安装到系统目录
install: $(KERN_OBJ)
	@echo "[*] 安装到 /opt/netmonitor ..."
	install -d /opt/netmonitor/ebpf
	install -m 644 $(KERN_OBJ) /opt/netmonitor/ebpf/
	install -m 755 netmon_user.py /opt/netmonitor/ebpf/
	@echo "[✓] 安装完成"

uninstall:
	@echo "[*] 卸载 /opt/netmonitor/ebpf ..."
	rm -rf /opt/netmonitor/ebpf
	@echo "[✓] 卸载完成"

# 代码格式化（需要 clang-format）
format:
	@command -v clang-format >/dev/null 2>&1 && \
		clang-format -i $(KERN_SRC) && echo "[✓] 格式化完成" || \
		echo "[!] clang-format 未安装，跳过"

# 静态检查
check: $(KERN_OBJ)
	@echo "[*] 验证 eBPF 程序 ..."
	$(BPFTOOL) prog load $(KERN_OBJ) /sys/fs/bpf/netmon_check 2>/dev/null && \
		$(BPFTOOL) prog detach pinned /sys/fs/bpf/netmon_check && \
		rm -f /sys/fs/bpf/netmon_check && \
		echo "[✓] 验证通过" || \
		echo "[!] 验证失败（可能需要 root 权限）"

clean:
	rm -f $(KERN_OBJ)
	@echo "[✓] 清理完成"

help:
	@echo "NetMonitor Pro eBPF Makefile"
	@echo ""
	@echo "目标:"
	@echo "  all        编译 eBPF 内核探针 (默认)"
	@echo "  vmlinux    生成 vmlinux.h"
	@echo "  install    安装到 /opt/netmonitor"
	@echo "  uninstall  从系统卸载"
	@echo "  format     格式化代码"
	@echo "  check      静态检查 eBPF 程序"
	@echo "  clean      清理编译产物"
	@echo "  help       显示此帮助"