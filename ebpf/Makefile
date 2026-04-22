# NetMonitor Pro — eBPF 模块构建
# 用法: make          # 编译 BPF 目标文件
#       make clean    # 清理
#       make run      # 编译并运行（需要 root）

CLANG     ?= clang
LLC       ?= llc
ARCH      := $(shell uname -m | sed 's/x86_64/x86/' | sed 's/aarch64/arm64/')
KERN_SRC  := netmon_kern.c
KERN_OBJ  := netmon_kern.o

# 内核头文件路径（根据实际环境调整）
KERN_HEADERS := /usr/include
BPF_HEADERS  := /usr/include/bpf

CFLAGS := -O2 -g -target bpf \
          -D__TARGET_ARCH_$(ARCH) \
          -I$(KERN_HEADERS) \
          -I$(BPF_HEADERS) \
          -Wall -Werror

.PHONY: all clean run

all: $(KERN_OBJ)

$(KERN_OBJ): $(KERN_SRC)
	$(CLANG) $(CFLAGS) -c $< -o $@
	@echo "✅ 编译完成: $@"

clean:
	rm -f $(KERN_OBJ)
	@echo "🧹 已清理"

run: all
	@echo "🚀 启动 NetMonitor eBPF..."
	sudo python3 netmon_user.py

run-filtered:
	@echo "🚀 启动 NetMonitor eBPF (UID 过滤模式)..."
	sudo python3 netmon_user.py --uid $(UID)

run-log:
	@echo "🚀 启动 NetMonitor eBPF (日志模式)..."
	sudo python3 netmon_user.py --log-file /var/log/netmon/events.jsonl
