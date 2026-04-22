#!/usr/bin/env python3
"""
NetMonitor Pro — eBPF 用户态加载器（致命级修复版）
[FIX-#3] 时间戳转换修正  [FIX-#4] 键名event→event_type
"""

import ctypes, json, os, signal, socket, struct, sys, time
import threading, argparse, logging
from datetime import datetime, timezone
from collections import deque
from pathlib import Path

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

logging.basicConfig(level=logging.INFO, format="%(asctime)s [%(levelname)s] %(message)s", datefmt="%Y-%m-%d %H:%M:%S")
log = logging.getLogger("netmon")

TASK_COMM_LEN = 16
EVENT_TYPES = {1: "TCP_CONNECT", 2: "TCP_CONNECT_RET", 3: "UDP_SEND", 4: "TCP_CLOSE", 5: "DNS_QUERY"}
PROTOCOLS = {6: "TCP", 17: "UDP"}

# ── [FIX-#3] 计算内核单调时钟到壁钟的偏移 ──
# bpf_ktime_get_ns() 返回 CLOCK_MONOTONIC，不是 Unix 时间戳
# 需要加 boot_time 偏移才能转为正确的壁钟时间
_BOOT_TIME_SEC = time.time() - time.monotonic()  # ← FIX-#3

class In6Addr(ctypes.Structure):
    _fields_ = [("addr", ctypes.c_uint8 * 16)]

class NetEvent(ctypes.Structure):
    _fields_ = [
        ("timestamp_ns", ctypes.c_uint64), ("event_type", ctypes.c_uint32),
        ("pid", ctypes.c_uint32), ("tgid", ctypes.c_uint32),
        ("uid", ctypes.c_uint32), ("gid", ctypes.c_uint32),
        ("comm", ctypes.c_char * TASK_COMM_LEN),
        ("ip_version", ctypes.c_uint8), ("protocol", ctypes.c_uint8),
        ("src_port", ctypes.c_uint16), ("dst_port", ctypes.c_uint16),
        ("src_addr_v4", ctypes.c_uint32), ("dst_addr_v4", ctypes.c_uint32),
        ("src_addr_v6", In6Addr), ("dst_addr_v6", In6Addr),
        ("bytes_sent", ctypes.c_uint64), ("ret_val", ctypes.c_int32),
        ("addr_family", ctypes.c_uint16), ("_pad", ctypes.c_uint16),
    ]

def ipv4_to_str(addr): return socket.inet_ntoa(struct.pack("I", addr))
def ipv6_to_str(addr): return socket.inet_ntop(socket.AF_INET6, bytes(addr.addr))

def format_event(evt):
    is_v6 = evt.ip_version == 6
    wall_time = _BOOT_TIME_SEC + (evt.timestamp_ns / 1e9)  # ← FIX-#3
    d = {
        "timestamp": datetime.fromtimestamp(wall_time, tz=timezone.utc).isoformat(),  # ← FIX-#3
        "event_type": EVENT_TYPES.get(evt.event_type, f"UNKNOWN({evt.event_type})"),  # ← FIX-#4
        "pid": evt.pid, "tgid": evt.tgid, "uid": evt.uid, "gid": evt.gid,
        "comm": evt.comm.decode("utf-8", errors="replace").rstrip("\x00"),
        "ip_version": evt.ip_version,
        "protocol": PROTOCOLS.get(evt.protocol, str(evt.protocol)),
        "src_port": evt.src_port, "dst_port": evt.dst_port,
        "src_addr": ipv6_to_str(evt.src_addr_v6) if is_v6 else ipv4_to_str(evt.src_addr_v4),
        "dst_addr": ipv6_to_str(evt.dst_addr_v6) if is_v6 else ipv4_to_str(evt.dst_addr_v4),
        "bytes_sent": evt.bytes_sent,
    }
    if evt.event_type == 2:
        d["connect_result"] = "success" if evt.ret_val == 0 else f"error({evt.ret_val})"
    return d

class ReportWorker:
    def __init__(self, api_url, api_token, batch_size=50, flush_interval=5.0):
        self.api_url = api_url.rstrip("/")
        self.api_token = api_token
        self.batch_size = batch_size
        self.flush_interval = flush_interval
        self.buffer = deque(maxlen=100000)
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self): self._thread.start(); log.info("上报线程已启动 → %s", self.api_url)
    def stop(self): self._stop.set(); self._thread.join(timeout=10)
    def enqueue(self, event): self.buffer.append(event)

    def _run(self):
        while not self._stop.is_set():
            self._stop.wait(timeout=self.flush_interval)
            self._flush()
        self._flush()

    def _flush(self):
        if not self.buffer: return
        batch = []
        while self.buffer and len(batch) < self.batch_size:
            batch.append(self.buffer.popleft())
        if not batch: return
        try:
            resp = requests.post(f"{self.api_url}/ingest/batch", json={"events": batch},
                headers={"Authorization": f"Bearer {self.api_token}", "Content-Type": "application/json"}, timeout=10)
            if resp.status_code in (200, 207): log.debug("上报 %d 条成功", len(batch))
            else: log.warning("上报失败: HTTP %d", resp.status_code)
        except Exception as e:
            log.error("上报异常: %s", e)
            for item in reversed(batch): self.buffer.appendleft(item)

class JsonLogger:
    FLUSH_INTERVAL = 50
    def __init__(self, path):
        self.path = Path(path); self.path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(self.path, "a", encoding="utf-8"); self._count = 0
    def write(self, event):
        self._file.write(json.dumps(event, ensure_ascii=False) + "\n")
        self._count += 1
        if self._count % self.FLUSH_INTERVAL == 0: self._file.flush()
    def close(self): self._file.flush(); self._file.close()

def parse_args():
    p = argparse.ArgumentParser(description="NetMonitor Pro eBPF 用户态加载器")
    p.add_argument("--uid", type=int, nargs="*")
    p.add_argument("--no-udp", action="store_true")
    p.add_argument("--api-url", type=str, default=None)
    p.add_argument("--api-token", type=str, default=None)
    p.add_argument("--log-file", type=str, default=None)
    p.add_argument("--batch-size", type=int, default=50)
    p.add_argument("-v", "--verbose", action="store_true")
    return p.parse_args()

def print_event_line(evt_dict):
    ev = evt_dict["event_type"]  # ← FIX-#4
    comm, pid, proto = evt_dict["comm"], evt_dict["pid"], evt_dict["protocol"]
    src = f"{evt_dict['src_addr']}:{evt_dict['src_port']}"
    dst = f"{evt_dict['dst_addr']}:{evt_dict['dst_port']}"
    colors = {"TCP_CONNECT":"\033[32m","TCP_CONNECT_RET":"\033[36m","UDP_SEND":"\033[33m","TCP_CLOSE":"\033[31m","DNS_QUERY":"\033[35m"}
    c, r = colors.get(ev, "\033[0m"), "\033[0m"
    extra = ""
    if "connect_result" in evt_dict: extra = f" [{evt_dict['connect_result']}]"
    if evt_dict["bytes_sent"] > 0: extra += f" {evt_dict['bytes_sent']}B"
    print(f"{c}[{ev:18s}]{r} {proto:3s} {comm:16s} pid={pid:<7d} {src:>21s} → {dst:<21s}{extra}")

def main():
    args = parse_args()
    if not HAS_BCC: log.error("缺少 bcc 依赖"); sys.exit(1)
    if args.verbose: log.setLevel(logging.DEBUG)

    src_path = Path(__file__).parent / "netmon_kern.c"
    if not src_path.exists(): log.error("找不到 %s", src_path); sys.exit(1)

    log.info("编译加载 eBPF 程序...")
    b = BPF(src_file=str(src_path), cflags=["-O2", "-g"])

    config_map = b["global_config"]
    class ConfigVal(ctypes.Structure):
        _fields_ = [("filter_enabled", ctypes.c_uint8), ("capture_udp", ctypes.c_uint8), ("_pad", ctypes.c_uint16)]
    cfg = ConfigVal()
    cfg.capture_udp = 0 if args.no_udp else 1
    if args.uid:
        cfg.filter_enabled = 1
        uid_map = b["uid_filter"]
        for uid in args.uid: uid_map[ctypes.c_uint32(uid)] = ctypes.c_uint8(1); log.info("UID 过滤: %d", uid)
    else: cfg.filter_enabled = 0
    config_map[ctypes.c_uint32(0)] = cfg

    reporter = None
    if args.api_url and args.api_token:
        if HAS_REQUESTS: reporter = ReportWorker(args.api_url, args.api_token, args.batch_size); reporter.start()
        else: log.warning("缺少 requests 库")
    json_logger = JsonLogger(args.log_file) if args.log_file else None
    stats = {"total": 0, "tcp": 0, "udp": 0, "dns": 0, "errors": 0}

    def handle_event(ctx, data, size):
        evt = ctypes.cast(data, ctypes.POINTER(NetEvent)).contents
        evt_dict = format_event(evt)
        stats["total"] += 1
        if evt.protocol == 6: stats["tcp"] += 1
        elif evt.protocol == 17: stats["udp"] += 1
        if evt.event_type == 5: stats["dns"] += 1
        if evt.event_type == 2 and evt.ret_val != 0: stats["errors"] += 1
        print_event_line(evt_dict)
        if reporter: reporter.enqueue(evt_dict)
        if json_logger: json_logger.write(evt_dict)

    b["events"].open_ring_buffer(handle_event)
    running = True
    def on_signal(s, f): nonlocal running; running = False; print("\n停止中...")
    signal.signal(signal.SIGINT, on_signal); signal.signal(signal.SIGTERM, on_signal)

    log.info("=" * 60)
    log.info("NetMonitor Pro eBPF 已启动 — Ctrl+C 停止")
    log.info("=" * 60)
    print(f"{'事件类型':18s}  协议  {'进程名':16s} {'PID':7s}  {'源地址':>21s}    {'目标地址':<21s}")
    print("-" * 100)

    while running:
        try: b.ring_buffer_poll(timeout=100)
        except Exception as e: log.error("异常: %s", e); break

    if reporter: reporter.stop()
    if json_logger: json_logger.close()
    log.info("统计: 总=%d TCP=%d UDP=%d DNS=%d 错误=%d", stats["total"], stats["tcp"], stats["udp"], stats["dns"], stats["errors"])

if __name__ == "__main__": main()