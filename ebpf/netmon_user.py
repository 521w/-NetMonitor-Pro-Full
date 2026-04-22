#!/usr/bin/env python3
"""
NetMonitor Pro — eBPF 用户态加载器 & 事件消费者
功能：
  1. 编译并加载 netmon_kern.c 到内核
  2. 从 ring buffer 实时读取网络事件
  3. 本地格式化输出 + 批量上报到云端 API
  4. 支持 UID 过滤、JSON 导出、PCAP-like 日志

依赖：bcc (BPF Compiler Collection) — pip install bcc 或系统包
"""

import ctypes
import json
import os
import signal
import socket
import struct
import sys
import time
import threading
import argparse
import logging
from datetime import datetime, timezone
from collections import deque
from pathlib import Path

# ─── 可选依赖 ───
try:
    import requests
    HAS_REQUESTS = True
except ImportError:
    HAS_REQUESTS = False

try:
    from bcc import BPF
    HAS_BCC = True
except ImportError:
    HAS_BCC = False

# ─── 日志配置 ───
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    datefmt="%Y-%m-%d %H:%M:%S"
)
log = logging.getLogger("netmon")

# ─── 常量 ───
TASK_COMM_LEN = 16

EVENT_TYPES = {
    1: "TCP_CONNECT",
    2: "TCP_CONNECT_RET",
    3: "UDP_SEND",
    4: "TCP_CLOSE",
    5: "DNS_QUERY",
}

PROTOCOLS = {
    6:  "TCP",
    17: "UDP",
}

# ─── ctypes 结构体 — 必须与 netmon_kern.c 保持一致 ───

class In6Addr(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint8 * 16)]

class NetEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns",   ctypes.c_uint64),
        ("event_type",     ctypes.c_uint32),
        ("pid",            ctypes.c_uint32),
        ("tgid",           ctypes.c_uint32),
        ("uid",            ctypes.c_uint32),
        ("gid",            ctypes.c_uint32),
        ("comm",           ctypes.c_char * TASK_COMM_LEN),
        ("ip_version",     ctypes.c_uint8),
        ("protocol",       ctypes.c_uint8),
        ("src_port",       ctypes.c_uint16),
        ("dst_port",       ctypes.c_uint16),
        ("src_addr_v4",    ctypes.c_uint32),
        ("dst_addr_v4",    ctypes.c_uint32),
        ("src_addr_v6",    In6Addr),
        ("dst_addr_v6",    In6Addr),
        ("bytes_sent",     ctypes.c_uint64),
        ("ret_val",        ctypes.c_int32),
        ("addr_family",    ctypes.c_uint16),
        ("_pad",           ctypes.c_uint16),
    ]


def ipv4_to_str(addr: int) -> str:
    """将网络序 u32 转为点分十进制字符串"""
    return socket.inet_ntoa(struct.pack("I", addr))


def ipv6_to_str(addr: In6Addr) -> str:
    """将 16 字节数组转为 IPv6 字符串"""
    return socket.inet_ntop(socket.AF_INET6, bytes(addr.addr))


def format_event(evt: NetEvent) -> dict:
    """将 C 结构体转为 Python 字典"""
    is_v6 = evt.ip_version == 6
    d = {
        "timestamp":  datetime.fromtimestamp(
            evt.timestamp_ns / 1e9, tz=timezone.utc
        ).isoformat(),
        "event":      EVENT_TYPES.get(evt.event_type, f"UNKNOWN({evt.event_type})"),
        "pid":        evt.pid,
        "tgid":       evt.tgid,
        "uid":        evt.uid,
        "gid":        evt.gid,
        "comm":       evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "ip_version": evt.ip_version,
        "protocol":   PROTOCOLS.get(evt.protocol, str(evt.protocol)),
        "src_port":   evt.src_port,
        "dst_port":   evt.dst_port,
        "src_addr":   ipv6_to_str(evt.src_addr_v6) if is_v6 else ipv4_to_str(evt.src_addr_v4),
        "dst_addr":   ipv6_to_str(evt.dst_addr_v6) if is_v6 else ipv4_to_str(evt.dst_addr_v4),
        "bytes_sent": evt.bytes_sent,
    }
    if evt.event_type == 2:  # TCP_CONNECT_RET
        d["connect_result"] = "success" if evt.ret_val == 0 else f"error({evt.ret_val})"
    return d


# ─── 上报线程 ───

class ReportWorker:
    """批量异步上报事件到云端 API"""

    def __init__(self, api_url: str, api_token: str, batch_size: int = 50,
                 flush_interval: float = 5.0):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = deque(maxlen=100000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        log.info("上报线程已启动 → %s", self.api_url)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)

    def enqueue(self, event: dict):
        self.buffer.append(event)

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(timeout=self.flush_interval)
            self._flush()
        self._flush()  # 退出前最终刷新

    def _flush(self):
        if not self.buffer:
            return
        batch = []
        while self.buffer and len(batch) < self.batch_size:
            batch.append(self.buffer.popleft())
        if not batch:
            return
        try:
            resp = requests.post(
                f"{self.api_url}/ingest/batch",
                json={"events": batch},
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            if resp.status_code == 200:
                log.debug("上报 %d 条事件成功", len(batch))
            else:
                log.warning("上报失败: HTTP %d — %s", resp.status_code, resp.text[:200])
        except Exception as e:
            log.error("上报异常: %s", e)
            # 回退到缓冲区头部
            for item in reversed(batch):
                self.buffer.appendleft(item)


# ─── JSON 日志写入 ───

class JsonLogger:
    """将事件追加写入 JSON Lines 文件"""

    def __init__(self, path: str):
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8")
        log.info("日志文件: %s", self.path)

    def write(self, event: dict):
        self._file.write(json.dumps(event, ensure_ascii=False) + "\n")

    def close(self):
        self._file.flush()
        self._file.close()


# ─── 主程序 ───

def parse_args():
    p = argparse.ArgumentParser(description="NetMonitor Pro eBPF 用户态加载器")
    p.add_argument("--uid", type=int, nargs="*",
                    help="仅监控指定 UID（不指定则全量采集）")
    p.add_argument("--no-udp", action="store_true",
                    help="不采集 UDP 事件")
    p.add_argument("--api-url", type=str, default=None,
                    help="云端 API 地址 (例: https://your-server.com/api/v1)")
    p.add_argument("--api-token", type=str, default=None,
                    help="API 认证令牌")
    p.add_argument("--log-file", type=str, default=None,
                    help="JSON 日志文件路径")
    p.add_argument("--batch-size", type=int, default=50,
                    help="批量上报数量（默认 50）")
    p.add_argument("-v", "--verbose", action="store_true",
                    help="详细输出")
    return p.parse_args()


def print_event_line(evt_dict: dict):
    """终端格式化输出单条事件"""
    ev   = evt_dict["event"]
    comm = evt_dict["comm"]
    pid  = evt_dict["pid"]
    proto = evt_dict["protocol"]
    src  = f"{evt_dict['src_addr']}:{evt_dict['src_port']}"
    dst  = f"{evt_dict['dst_addr']}:{evt_dict['dst_port']}"

    # 颜色编码
    colors = {
        "TCP_CONNECT":     "\033[32m",   # 绿
        "TCP_CONNECT_RET": "\033[36m",   # 青
        "UDP_SEND":        "\033[33m",   # 黄
        "TCP_CLOSE":       "\033[31m",   # 红
        "DNS_QUERY":       "\033[35m",   # 紫
    }
    c = colors.get(ev, "\033[0m")
    r = "\033[0m"

    extra = ""
    if "connect_result" in evt_dict:
        extra = f" [{evt_dict['connect_result']}]"
    if evt_dict["bytes_sent"] > 0:
        extra += f" {evt_dict['bytes_sent']}B"

    print(f"{c}[{ev:18s}]{r} {proto:3s} {comm:16s} pid={pid:<7d} "
          f"{src:>21s} → {dst:<21s}{extra}")


def main():
    args = parse_args()

    if not HAS_BCC:
        log.error("缺少 bcc 依赖。请安装: apt install bpfcc-tools python3-bcc")
        sys.exit(1)

    if args.verbose:
        log.setLevel(logging.DEBUG)

    # ─── 编译加载 BPF 程序 ───
    src_path = Path(__file__).parent / "netmon_kern.c"
    if not src_path.exists():
        log.error("找不到 eBPF 源文件: %s", src_path)
        sys.exit(1)

    log.info("编译加载 eBPF 程序...")
    b = BPF(src_file=str(src_path), cflags=["-O2", "-g"])

    # ─── 配置过滤器 ───
    config_map = b["global_config"]
    cfg_key = ctypes.c_uint32(0)

    class ConfigVal(ctypes.Structure):
        _fields_ = [
            ("filter_enabled", ctypes.c_uint8),
            ("capture_udp",    ctypes.c_uint8),
            ("_pad",           ctypes.c_uint16),
        ]

    cfg = ConfigVal()
    cfg.capture_udp = 0 if args.no_udp else 1

    if args.uid:
        cfg.filter_enabled = 1
        uid_filter_map = b["uid_filter"]
        for uid in args.uid:
            uid_filter_map[ctypes.c_uint32(uid)] = ctypes.c_uint8(1)
            log.info("添加 UID 过滤: %d", uid)
    else:
        cfg.filter_enabled = 0

    config_map[cfg_key] = cfg

    # ─── 初始化输出组件 ───
    reporter = None
    if args.api_url and args.api_token:
        if not HAS_REQUESTS:
            log.warning("缺少 requests 库，跳过 API 上报。pip install requests")
        else:
            reporter = ReportWorker(
                api_url=args.api_url,
                api_token=args.api_token,
                batch_size=args.batch_size,
            )
            reporter.start()

    json_logger = None
    if args.log_file:
        json_logger = JsonLogger(args.log_file)

    # ─── 事件计数器 ───
    stats = {"total": 0, "tcp": 0, "udp": 0, "dns": 0, "errors": 0}

    # ─── ring buffer 回调 ───
    def handle_event(ctx, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
        evt_dict = format_event(evt)

        stats["total"] += 1
        if evt.protocol == 6:
            stats["tcp"] += 1
        elif evt.protocol == 17:
            stats["udp"] += 1
        if evt.event_type == 5:
            stats["dns"] += 1
        if evt.event_type == 2 and evt.ret_val != 0:
            stats["errors"] += 1

        print_event_line(evt_dict)

        if reporter:
            reporter.enqueue(evt_dict)
        if json_logger:
            json_logger.write(evt_dict)

    b["events"].open_ring_buffer(handle_event)

    # ─── 优雅退出 ───
    running = True

    def on_signal(signum, frame):
        nonlocal running
        running = False
        print("\n正在停止...")

    signal.signal(signal.SIGINT, on_signal)
    signal.signal(signal.SIGTERM, on_signal)

    # ─── 主循环 ───
    log.info("=" * 60)
    log.info("NetMonitor Pro eBPF 已启动 — 按 Ctrl+C 停止")
    log.info("UDP 采集: %s | UID 过滤: %s",
             "开启" if cfg.capture_udp else "关闭",
             str(args.uid) if args.uid else "关闭（全量）")
    log.info("=" * 60)

    print(f"{'事件类型':18s}  协议  {'进程名':16s} {'PID':7s}  "
          f"{'源地址':>21s}    {'目标地址':<21s}")
    print("-" * 100)

    while running:
        try:
            b.ring_buffer_poll(timeout=100)
        except Exception as e:
            log.error("ring buffer 轮询异常: %s", e)
            break

    # ─── 清理 ───
    if reporter:
        reporter.stop()
    if json_logger:
        json_logger.close()

    log.info("统计: 总计=%d TCP=%d UDP=%d DNS=%d 错误=%d",
             stats["total"], stats["tcp"], stats["udp"],
             stats["dns"], stats["errors"])


if __name__ == "__main__":
    main()
