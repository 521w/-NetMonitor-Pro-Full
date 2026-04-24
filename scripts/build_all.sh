#!/bin/bash
# ============================================================
# NetMonitor Pro — 全模块构建脚本 (重写版)
# 文件位置: scripts/build_all.sh
#
# 优化点:
#   1. [致命修复] 原脚本是假的！只 echo 打印命令没有真正执行编译
#      现在全部改为真正执行
#   2. 增加 set -euo pipefail 严格模式，任何命令失败立即停止
#   3. 新增 Android 模块构建（原脚本名为 build_all 但不构建 Android）
#   4. 新增 Python 依赖安装（原脚本不处理 server 依赖）
#   5. zip 排除 .git 目录（原脚本会把仓库历史打包泄漏）
#   6. 增加构建耗时统计和彩色输出
# ============================================================

set -euo pipefail

# ────────────────────── 变量 ──────────────────────

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
ROOT_DIR="$(dirname "$SCRIPT_DIR")"
BUILD_START=$(date +%s)

# 颜色定义
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# ────────────────────── 工具函数 ──────────────────────

log_info()  { echo -e "${BLUE}[INFO]${NC}  $*"; }
log_ok()    { echo -e "${GREEN}[✓]${NC}    $*"; }
log_warn()  { echo -e "${YELLOW}[⚠]${NC}    $*"; }
log_error() { echo -e "${RED}[✗]${NC}    $*"; }

check_command() {
    if ! command -v "$1" &>/dev/null; then
        log_error "缺少依赖: $1"
        return 1
    fi
}

# ────────────────────── 头部 ──────────────────────

echo ""
echo "=========================================="
echo " NetMonitor Pro — Full Build"
echo " $(date '+%Y-%m-%d %H:%M:%S')"
echo "=========================================="
echo ""

# ────────────────────── 环境检查 ──────────────────────

log_info "检查构建环境..."

MISSING=0
for cmd in clang llc make zip python3 pip3; do
    if check_command "$cmd"; then
        log_ok "$cmd: $(command -v "$cmd")"
    else
        MISSING=$((MISSING + 1))
    fi
done

if [ "$MISSING" -gt 0 ]; then
    log_error "缺少 $MISSING 个依赖工具，请先安装"
    exit 1
fi

echo ""

# ────────────────────── 1. 构建 eBPF 内核模块 ──────────────────────

log_info "[1/4] 构建 eBPF 内核模块..."
cd "$ROOT_DIR/ebpf"

if [ -f Makefile ]; then
    make clean 2>/dev/null || true
    make
    log_ok "eBPF 模块编译完成"
else
    log_warn "ebpf/Makefile 不存在，跳过 eBPF 构建"
fi

echo ""

# ────────────────────── 2. 安装 Python 依赖 ──────────────────────

log_info "[2/4] 安装服务端 Python 依赖..."
cd "$ROOT_DIR/server"

if [ -f requirements.txt ]; then
    pip3 install -r requirements.txt --quiet
    log_ok "Python 依赖安装完成"
elif [ -f requirements ]; then
    # 兼容旧文件名
    log_warn "发现旧格式 'requirements'，建议重命名为 'requirements.txt'"
    pip3 install -r requirements --quiet
    log_ok "Python 依赖安装完成（旧格式）"
else
    log_warn "未找到 requirements.txt，跳过依赖安装"
fi

echo ""

# ────────────────────── 3. 构建 Android 模块 ──────────────────────

log_info "[3/4] 构建 Android 模块..."
cd "$ROOT_DIR/android"

if [ -f gradlew ]; then
    chmod +x gradlew
    ./gradlew assembleRelease --no-daemon
    log_ok "Android APK 构建完成"

    # 尝试输出 APK 路径
    APK_PATH=$(find . -name "*.apk" -path "*/release/*" 2>/dev/null | head -1)
    if [ -n "$APK_PATH" ]; then
        log_info "APK 位置: $APK_PATH"
    fi
elif [ -f build.gradle.kts ] || [ -f build.gradle ]; then
    log_warn "找到 Gradle 配置但缺少 gradlew，请运行: gradle wrapper"
    log_warn "跳过 Android 构建"
else
    log_warn "未找到 Android 项目配置，跳过"
fi

echo ""

# ────────────────────── 4. 打包发布 ──────────────────────

log_info "[4/4] 打包发布包..."
cd "$ROOT_DIR"

OUTPUT_FILE="NetMonitor-Pro-Full-$(date +%Y%m%d).zip"

# [修复] 排除 .git、编译中间产物、敏感数据
zip -r "$OUTPUT_FILE" . \
    -x ".git/*" \
    -x ".git*" \
    -x "*.o" \
    -x "*.ko" \
    -x "__pycache__/*" \
    -x "*.pyc" \
    -x "*.pyo" \
    -x "server/data/*" \
    -x "server/.jwt_secret" \
    -x "android/.gradle/*" \
    -x "android/build/*" \
    -x "android/app/build/*" \
    -x "*.zip" \
    -x ".env" \
    -x ".env.*" \
    > /dev/null

log_ok "发布包: $OUTPUT_FILE"
log_info "文件大小: $(du -h "$OUTPUT_FILE" | cut -f1)"

echo ""

# ────────────────────── 完成 ──────────────────────

BUILD_END=$(date +%s)
BUILD_TIME=$((BUILD_END - BUILD_START))

echo "=========================================="
echo -e " ${GREEN}✅ 构建完成${NC}"
echo " 耗时: ${BUILD_TIME} 秒"
echo " 输出: $OUTPUT_FILE"
echo "=========================================="
echo ""
