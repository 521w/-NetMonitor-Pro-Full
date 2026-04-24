#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
NetMonitor Pro — eBPF 用户态加载器 + 事件消费 (优化版)
文件位置: ebpf/netmon_user.py

优化点:
  1. 动态计算 boot time offset，防止长时间运行后时间戳漂移
  2. ReportWorker 增加指数退避重试 + 连续失败计数保护，防止静默丢数据
  3. JsonLogger 增加异常保护，磁盘满时不崩溃
  4. 主循环异常容忍机制，一次暂时错误不再终止整个监控
  5. 新增 --device-id 参数，上报时附加设备标识
  6. 新增优雅退出和资源清理
"""

import argparse
import ctypes
import json
import logging
import os
import signal
import socket
import struct
import sys
import threading
import time
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

try:
    from bcc import BPF
except ImportError:
    print("错误: 需要安装 bcc (BPF Compiler Collection)")
    print("  Ubuntu/Debian: sudo apt install bpfcc-tools python3-bpfcc")
    print("  CentOS/RHEL:   sudo yum install bcc-tools python3-bcc")
    sys.exit(1)

try:
    import requests
except ImportError:
    requests = None  # 离线模式可用

# ────────────────────── 日志配置 ──────────────────────

log = logging.getLogger("netmon")

# ────────────────────── 常量 ──────────────────────

TASK_COMM_LEN = 16
ADDR_LEN_V6 = 16

EVENT_TYPE_MAP = {
    1: "TCP_CONNECT",
    2: "TCP_CONNECT_RET",
    3: "TCP_CLOSE",
    4: "UDP_SEND",
}

PROTOCOL_MAP = {
    6:  "TCP",
    17: "UDP",
}


# ────────────────────── 数据结构 (与内核端对齐) ──────────────────────

class NetEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64),
        ("pid",          ctypes.c_uint32),
        ("tgid",         ctypes.c_uint32),
        ("uid",          ctypes.c_uint32),
        ("gid",          ctypes.c_uint32),
        ("comm",         ctypes.c_char * TASK_COMM_LEN),
        ("event_type",   ctypes.c_uint8),
        ("ip_version",   ctypes.c_uint8),
        ("protocol",     ctypes.c_uint16),
        ("src_addr",     ctypes.c_uint8 * ADDR_LEN_V6),
        ("src_port",     ctypes.c_uint16),
        ("dst_addr",     ctypes.c_uint8 * ADDR_LEN_V6),
        ("dst_port",     ctypes.c_uint16),
        ("bytes_sent",   ctypes.c_uint64),
        ("ret_val",      ctypes.c_int32),
    ]


# ────────────────────── 工具函数 ──────────────────────

def get_wall_time_from_ktime(ktime_ns: int) -> float:
    """
    [优化] 每次调用时动态计算 boot offset，避免长时间运行后
    因 NTP 校时、suspend/resume 等导致的时间戳漂移。
    原实现: 模块加载时一次性计算 _BOOT_TIME_SEC，长期运行会漂移。
    """
    boot_offset = time.time() - time.monotonic()
    return boot_offset + (ktime_ns / 1e9)


def format_addr(raw: bytes, ip_version: int) -> str:
    """将原始字节转换为可读 IP 地址字符串"""
    if ip_version == 4:
        return socket.inet_ntop(socket.AF_INET, bytes(raw[:4]))
    elif ip_version == 6:
        return socket.inet_ntop(socket.AF_INET6, bytes(raw[:16]))
    return "unknown"


def event_to_dict(event: NetEvent, device_id: str = None) -> dict:
    """将 C 结构体转换为 Python 字典"""
    wall_time = get_wall_time_from_ktime(event.timestamp_ns)
    dt = datetime.fromtimestamp(wall_time, tz=timezone.utc)

    d = {
        "timestamp":   dt.isoformat(),
        "timestamp_ns": event.timestamp_ns,
        "event_type":  EVENT_TYPE_MAP.get(event.event_type,
                                          f"UNKNOWN_{event.event_type}"),
        "pid":         event.pid,
        "tgid":        event.tgid,
        "uid":         event.uid,
        "gid":         event.gid,
        "comm":        event.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "ip_version":  event.ip_version,
        "protocol":    PROTOCOL_MAP.get(event.protocol,
                                        str(event.protocol)),
        "src_addr":    format_addr(event.src_addr, event.ip_version),
        "src_port":    event.src_port,
        "dst_addr":    format_addr(event.dst_addr, event.ip_version),
        "dst_port":    event.dst_port,
        "bytes_sent":  event.bytes_sent,
        "ret_val":     event.ret_val,
    }

    if device_id:
        d["device_id"] = device_id

    return d


# ────────────────────── JsonLogger ──────────────────────

class JsonLogger:
    """
    本地 JSON 日志写入器。
    [优化] 增加异常保护，磁盘满时不崩溃，只记录错误。
    """
    FLUSH_INTERVAL = 50  # 每 50 条 flush 一次

    def __init__(self, log_dir: str, prefix: str = "netmon"):
        self._dir = Path(log_dir)
        self._dir.mkdir(parents=True, exist_ok=True)
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        self._path = self._dir / f"{prefix}_{ts}.jsonl"
        self._file = open(self._path, "a", encoding="utf-8")
        self._count = 0
        log.info("日志文件: %s", self._path)

    def write(self, event: dict):
        """[优化] 捕获 OSError，磁盘满时不崩溃"""
        try:
            self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
            self._count += 1
            if self._count % self.FLUSH_INTERVAL == 0:
                self._file.flush()
        except OSError as e:
            log.error("日志写入失败 (已写 %d 条): %s", self._count, e)

    def close(self):
        try:
            self._file.flush()
            self._file.close()
        except OSError:
            pass
        log.info("日志关闭，共写入 %d 条", self._count)

    @property
    def count(self):
        return self._count


# ────────────────────── ReportWorker ──────────────────────

class ReportWorker:
    """
    后台线程：批量上报事件到服务端 API。

    [优化]:
      - 指数退避重试，API 故障时不暴力重试加剧服务端压力
      - 连续失败超限后主动丢弃批次，避免 deque 无限堆积导致静默丢数据
      - 成功上报后立即重置退避计数
    """
    MAX_RETRIES = 5

    def __init__(self, api_url: str, api_token: str,
                 device_id: str = None,
                 batch_size: int = 50,
                 flush_interval: float = 5.0):
        if requests is None:
            raise ImportError("上报功能需要 requests 库: pip install requests")

        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.device_id = device_id
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = deque(maxlen=100000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True,
                                        name="report-worker")
        self._consecutive_failures = 0
        self._total_sent = 0
        self._total_dropped = 0

    def start(self):
        self._thread.start()
        log.info("上报线程已启动 -> %s", self.api_url)

    def stop(self):
        self._stop.set()
        self._thread.join(timeout=10)
        log.info("上报线程已停止 (已发送 %d, 丢弃 %d)",
                 self._total_sent, self._total_dropped)

    def enqueue(self, event: dict):
        self.buffer.append(event)

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
                f"{self.api_url}/api/v1/ingest/batch",
                json={"events": batch},
                headers={
                    "Authorization": f"Bearer {self.api_token}",
                    "Content-Type": "application/json",
                },
                timeout=10,
            )
            if resp.status_code in (200, 207):
                self._total_sent += len(batch)
                self._consecutive_failures = 0
                log.debug("上报 %d 条成功 (累计 %d)",
                          len(batch), self._total_sent)
            else:
                raise Exception(f"HTTP {resp.status_code}: {resp.text[:200]}")

        except Exception as e:
            self._consecutive_failures += 1
            log.error("上报异常 (连续第 %d 次): %s",
                      self._consecutive_failures, e)

            # [优化] 超过最大重试次数就丢弃，避免无限堆积
            if self._consecutive_failures <= self.MAX_RETRIES:
                # 放回队首重试
                for item in reversed(batch):
                    self.buffer.appendleft(item)
            else:
                self._total_dropped += len(batch)
                log.warning("连续失败超 %d 次，丢弃 %d 条数据 (累计丢弃 %d)",
                            self.MAX_RETRIES, len(batch), self._total_dropped)

    def _run(self):
        while not self._stop.is_set():
            # [优化] 指数退避等待
            backoff = min(
                self.flush_interval * (2 ** self._consecutive_failures),
                60.0
            )
            self._stop.wait(timeout=backoff)
            self._flush()

        # 退出前最后一次 flush
        self._flush()


# ────────────────────── 事件回调 ──────────────────────

class EventHandler:
    """统一管理事件分发：控制台打印 + 本地日志 + 远程上报"""

    def __init__(self, args):
        self.verbose = args.verbose
        self.device_id = args.device_id
        self.logger = None
        self.reporter = None
        self._count = 0

        # 本地日志
        if args.log_dir:
            self.logger = JsonLogger(args.log_dir)

        # 远程上报
        if args.api_url and args.api_token:
            self.reporter = ReportWorker(
                api_url=args.api_url,
                api_token=args.api_token,
                device_id=args.device_id,
                batch_size=args.batch_size,
                flush_interval=args.flush_interval,
            )
            self.reporter.start()

    def handle(self, ctx, data, size):
        event = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
        d = event_to_dict(event, self.device_id)
        self._count += 1

        # 控制台输出
        if self.verbose:
            self._print_event(d)

        # 本地日志
        if self.logger:
            self.logger.write(d)

        # 远程上报
        if self.reporter:
            self.reporter.enqueue(d)

    def _print_event(self, d: dict):
        print(
            f"[{d['timestamp']}] "
            f"{d['event_type']:20s} "
            f"pid={d['pid']:<6d} "
            f"uid={d['uid']:<6d} "
            f"{d['comm']:16s} "
            f"{d['protocol']} "
            f"{d['src_addr']}:{d['src_port']} -> "
            f"{d['dst_addr']}:{d['dst_port']}"
            f"{f'  bytes={d[\"bytes_sent\"]}' if d['bytes_sent'] else ''}"
            f"{f'  ret={d[\"ret_val\"]}' if d['event_type'] == 'TCP_CONNECT_RET' else ''}"
        )

    def close(self):
        if self.logger:
            self.logger.close()
        if self.reporter:
            self.reporter.stop()

    @property
    def count(self):
        return self._count


# ────────────────────── 主程序 ──────────────────────

def parse_args():
    p = argparse.ArgumentParser(
        description="NetMonitor Pro — eBPF 网络监控工具",
        formatter_class=argparse.RawDescriptionHelpFormatter,
    )
    p.add_argument("-v", "--verbose", action="store_true",
                   help="控制台打印每条事件")
    p.add_argument("--log-dir", type=str, default=None,
                   help="本地 JSONL 日志输出目录")
    p.add_argument("--api-url", type=str, default=None,
                   help="服务端 API 地址 (如 http://server:5000)")
    p.add_argument("--api-token", type=str, default=None,
                   help="API 认证 token")
    p.add_argument("--device-id", type=str, default=None,
                   help="[新增] 设备标识，上报时附加到每条事件")
    p.add_argument("--batch-size", type=int, default=50,
                   help="批量上报条数 (默认 50)")
    p.add_argument("--flush-interval", type=float, default=5.0,
                   help="上报间隔秒数 (默认 5.0)")
    p.add_argument("--target-uid", type=int, default=0,
                   help="只监控指定 UID (0=全部)")
    p.add_argument("--target-pid", type=int, default=0,
                   help="只监控指定 PID (0=全部)")
    p.add_argument("--no-tcp", action="store_true",
                   help="不捕获 TCP 事件")
    p.add_argument("--no-udp", action="store_true",
                   help="不捕获 UDP 事件")
    return p.parse_args()


def load_ebpf(args) -> BPF:
    """加载 eBPF 程序"""
    src_path = Path(__file__).parent / "netmon_kern.c"

    # 注意: 生产环境应使用预编译的 .o 文件通过 BPF.load_func
    # 这里为了开发方便使用源码编译
    log.info("加载 eBPF 程序: %s", src_path)
    b = BPF(src_file=str(src_path))

    # 设置全局配置
    config_map = b["global_config"]
    key = ctypes.c_uint32(0)

    class Config(ctypes.Structure):
        _fields_ = [
            ("capture_tcp", ctypes.c_uint8),
            ("capture_udp", ctypes.c_uint8),
            ("target_uid",  ctypes.c_uint32),
            ("target_pid",  ctypes.c_uint32),
        ]

    cfg = Config()
    cfg.capture_tcp = 0 if args.no_tcp else 1
    cfg.capture_udp = 0 if args.no_udp else 1
    cfg.target_uid = args.target_uid
    cfg.target_pid = args.target_pid
    config_map[key] = cfg

    log.info("配置: tcp=%s, udp=%s, uid=%d, pid=%d",
             "ON" if cfg.capture_tcp else "OFF",
             "ON" if cfg.capture_udp else "OFF",
             cfg.target_uid, cfg.target_pid)

    return b


def main():
    args = parse_args()

    # 日志级别
    logging.basicConfig(
        level=logging.DEBUG if args.verbose else logging.INFO,
        format="%(asctime)s [%(name)s] %(levelname)s: %(message)s",
        datefmt="%Y-%m-%d %H:%M:%S",
    )

    # 权限检查
    if os.geteuid() != 0:
        log.error("需要 root 权限运行")
        sys.exit(1)

    # 加载 eBPF
    b = load_ebpf(args)

    # 事件处理器
    handler = EventHandler(args)

    # 注册 ringbuf 回调
    b["events"].open_ring_buffer(handler.handle)

    # 优雅退出
    running = True

    def signal_handler(signum, frame):
        nonlocal running
        sig_name = signal.Signals(signum).name
        log.info("收到信号 %s，正在退出...", sig_name)
        running = False

    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    log.info("NetMonitor Pro 已启动，按 Ctrl+C 退出")
    if args.device_id:
        log.info("设备标识: %s", args.device_id)

    # ── 主循环 ──
    # [优化] 异常容忍机制：一次暂时性错误不再终止整个监控
    error_count = 0
    MAX_CONSECUTIVE_ERRORS = 10

    while running:
        try:
            b.ring_buffer_poll(timeout=100)
            error_count = 0  # 成功时重置
        except KeyboardInterrupt:
            break
        except Exception as e:
            error_count += 1
            log.error("ringbuf 轮询异常 (连续第 %d 次): %s",
                      error_count, e)
            if error_count > MAX_CONSECUTIVE_ERRORS:
                log.critical("连续错误超 %d 次，退出", MAX_CONSECUTIVE_ERRORS)
                break
            time.sleep(1)  # 短暂等待后重试

    # ── 清理 ──
    log.info("正在清理资源...")
    handler.close()
    log.info("NetMonitor Pro 已退出，共处理 %d 条事件", handler.count)


if __name__ == "__main__":
    main()