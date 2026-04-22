// SPDX-License-Identifier: GPL-2.0
// NetMonitor Pro — eBPF 内核态网络事件采集模块
// 功能：hook TCP/UDP connect & sendmsg，采集完整五元组 + 元数据

#include <linux/bpf.h>
#include <linux/ptrace.h>
#include <linux/tcp.h>
#include <linux/udp.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/in.h>
#include <linux/in6.h>
#include <linux/socket.h>
#include <linux/net.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define AF_INET     2
#define AF_INET6    10
#define IPPROTO_TCP 6
#define IPPROTO_UDP 17
#define TASK_COMM_LEN 16

/* ────────────────────────── 数据结构 ────────────────────────── */

// 网络事件类型
enum event_type {
    EVENT_TCP_CONNECT = 1,    // TCP 连接发起
    EVENT_TCP_CONNECT_RET,    // TCP 连接结果（成功/失败）
    EVENT_UDP_SEND,           // UDP 发送
    EVENT_TCP_CLOSE,          // TCP 连接关闭
    EVENT_DNS_QUERY,          // DNS 查询（目标端口 53）
};

// IPv6 地址
struct in6_addr_t {
    __u8 addr[16];
};

// 网络事件结构体 — 完整五元组 + 进程元数据
struct net_event {
    // === 时间戳 & 事件类型 ===
    __u64 timestamp_ns;       // 内核单调时钟（纳秒）
    __u32 event_type;         // enum event_type

    // === 进程信息 ===
    __u32 pid;                // 进程 ID
    __u32 tgid;               // 线程组 ID
    __u32 uid;                // 用户 ID
    __u32 gid;                // 组 ID
    char  comm[TASK_COMM_LEN]; // 进程名

    // === 网络五元组 ===
    __u8  ip_version;         // 4 = IPv4, 6 = IPv6
    __u8  protocol;           // IPPROTO_TCP(6) / IPPROTO_UDP(17)
    __u16 src_port;           // 源端口（主机字节序）
    __u16 dst_port;           // 目标端口（主机字节序）
    __u32 src_addr_v4;        // IPv4 源地址
    __u32 dst_addr_v4;        // IPv4 目标地址
    struct in6_addr_t src_addr_v6; // IPv6 源地址
    struct in6_addr_t dst_addr_v6; // IPv6 目标地址

    // === 连接元数据 ===
    __u64 bytes_sent;         // 发送字节数（UDP 可用）
    __s32 ret_val;            // 系统调用返回值（connect 结果）
    __u16 addr_family;        // 地址族 AF_INET / AF_INET6
    __u16 _pad;               // 对齐填充
};

/* ────────────────────────── BPF Maps ────────────────────────── */

// Ring Buffer — 高性能事件输出通道
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);   // 16 MB
} events SEC(".maps");

// 存储 connect 入参，用于 kretprobe 关联
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);             // pid_tgid
    __type(value, struct net_event);
} connect_args SEC(".maps");

// 可配置过滤器 — 按 UID 过滤
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256);
    __type(key, __u32);             // uid
    __type(value, __u8);            // 1 = 监控此 uid
} uid_filter SEC(".maps");

// 全局配置
struct config {
    __u8  filter_enabled;     // 0 = 全量采集, 1 = 按 uid_filter 过滤
    __u8  capture_udp;        // 是否采集 UDP
    __u16 _pad;
};

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} global_config SEC(".maps");

/* ────────────────────────── 工具函数 ────────────────────────── */

// 检查是否需要过滤此 UID
static __always_inline int should_filter(__u32 uid) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &key);
    if (!cfg || !cfg->filter_enabled)
        return 0; // 不过滤，全量采集

    __u8 *val = bpf_map_lookup_elem(&uid_filter, &uid);
    return val ? 0 : 1; // 在白名单中 → 不过滤
}

// 填充进程基础信息
static __always_inline void fill_process_info(struct net_event *evt) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();

    evt->pid  = (__u32)(pid_tgid >> 32);
    evt->tgid = (__u32)(pid_tgid);
    evt->uid  = (__u32)(uid_gid);
    evt->gid  = (__u32)(uid_gid >> 32);
    evt->timestamp_ns = bpf_ktime_get_ns();

    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
}

/* ════════════════════════════════════════════════════════════════
 *  TCP CONNECT — kprobe / kretprobe
 *  hook tcp_v4_connect + tcp_v6_connect
 * ════════════════════════════════════════════════════════════════ */

// ─── tcp_v4_connect 入口 ───
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kprobe_tcp_v4_connect, struct sock *sk) {
    struct net_event evt = {};
    fill_process_info(&evt);

    if (should_filter(evt.uid))
        return 0;

    evt.event_type  = EVENT_TCP_CONNECT;
    evt.ip_version  = 4;
    evt.protocol    = IPPROTO_TCP;
    evt.addr_family = AF_INET;

    // 读取目标地址（connect 时 sk 已填充 daddr/dport）
    BPF_CORE_READ_INTO(&evt.dst_addr_v4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt.src_addr_v4, sk, __sk_common.skc_rcv_saddr);

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    evt.dst_port = bpf_ntohs(dport);

    __u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    evt.src_port = sport; // skc_num 已经是主机序

    // 暂存到 map，等 kretprobe 补充返回值
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_args, &pid_tgid, &evt, BPF_ANY);

    return 0;
}

// ─── tcp_v4_connect 返回 ───
SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(kretprobe_tcp_v4_connect, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct net_event *evt_ptr = bpf_map_lookup_elem(&connect_args, &pid_tgid);
    if (!evt_ptr)
        return 0;

    // 拷贝并补充返回值
    struct net_event *out = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!out) {
        bpf_map_delete_elem(&connect_args, &pid_tgid);
        return 0;
    }

    __builtin_memcpy(out, evt_ptr, sizeof(struct net_event));
    out->event_type = EVENT_TCP_CONNECT_RET;
    out->ret_val    = ret;
    out->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(out, 0);
    bpf_map_delete_elem(&connect_args, &pid_tgid);

    return 0;
}

// ─── tcp_v6_connect 入口 ───
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kprobe_tcp_v6_connect, struct sock *sk) {
    struct net_event evt = {};
    fill_process_info(&evt);

    if (should_filter(evt.uid))
        return 0;

    evt.event_type  = EVENT_TCP_CONNECT;
    evt.ip_version  = 6;
    evt.protocol    = IPPROTO_TCP;
    evt.addr_family = AF_INET6;

    // 读取 IPv6 地址
    BPF_CORE_READ_INTO(&evt.dst_addr_v6, sk,
                        __sk_common.skc_v6_daddr);
    BPF_CORE_READ_INTO(&evt.src_addr_v6, sk,
                        __sk_common.skc_v6_rcv_saddr);

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    evt.dst_port = bpf_ntohs(dport);

    __u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    evt.src_port = sport;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_args, &pid_tgid, &evt, BPF_ANY);

    return 0;
}

// ─── tcp_v6_connect 返回 ───
SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(kretprobe_tcp_v6_connect, int ret) {
    __u64 pid_tgid = bpf_get_current_pid_tgid();

    struct net_event *evt_ptr = bpf_map_lookup_elem(&connect_args, &pid_tgid);
    if (!evt_ptr)
        return 0;

    struct net_event *out = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!out) {
        bpf_map_delete_elem(&connect_args, &pid_tgid);
        return 0;
    }

    __builtin_memcpy(out, evt_ptr, sizeof(struct net_event));
    out->event_type = EVENT_TCP_CONNECT_RET;
    out->ret_val    = ret;
    out->timestamp_ns = bpf_ktime_get_ns();

    bpf_ringbuf_submit(out, 0);
    bpf_map_delete_elem(&connect_args, &pid_tgid);

    return 0;
}

/* ════════════════════════════════════════════════════════════════
 *  UDP SENDMSG — kprobe
 *  hook udp_sendmsg + udpv6_sendmsg
 * ════════════════════════════════════════════════════════════════ */

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kprobe_udp_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t len) {
    // 检查全局配置是否开启 UDP 采集
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &key);
    if (cfg && !cfg->capture_udp)
        return 0;

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(struct net_event));
    fill_process_info(evt);

    if (should_filter(evt->uid)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->event_type  = EVENT_UDP_SEND;
    evt->ip_version  = 4;
    evt->protocol    = IPPROTO_UDP;
    evt->addr_family = AF_INET;
    evt->bytes_sent  = (__u64)len;

    BPF_CORE_READ_INTO(&evt->dst_addr_v4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&evt->src_addr_v4, sk, __sk_common.skc_rcv_saddr);

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    evt->dst_port = bpf_ntohs(dport);

    __u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    evt->src_port = sport;

    // 标记 DNS 查询（目标端口 53）
    if (evt->dst_port == 53)
        evt->event_type = EVENT_DNS_QUERY;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kprobe_udpv6_sendmsg, struct sock *sk, struct msghdr *msg,
               size_t len) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &key);
    if (cfg && !cfg->capture_udp)
        return 0;

    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(struct net_event));
    fill_process_info(evt);

    if (should_filter(evt->uid)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->event_type  = EVENT_UDP_SEND;
    evt->ip_version  = 6;
    evt->protocol    = IPPROTO_UDP;
    evt->addr_family = AF_INET6;
    evt->bytes_sent  = (__u64)len;

    BPF_CORE_READ_INTO(&evt->dst_addr_v6, sk, __sk_common.skc_v6_daddr);
    BPF_CORE_READ_INTO(&evt->src_addr_v6, sk, __sk_common.skc_v6_rcv_saddr);

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    evt->dst_port = bpf_ntohs(dport);

    __u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    evt->src_port = sport;

    if (evt->dst_port == 53)
        evt->event_type = EVENT_DNS_QUERY;

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

/* ════════════════════════════════════════════════════════════════
 *  TCP CLOSE — 连接关闭事件
 * ════════════════════════════════════════════════════════════════ */

SEC("kprobe/tcp_close")
int BPF_KPROBE(kprobe_tcp_close, struct sock *sk) {
    struct net_event *evt = bpf_ringbuf_reserve(&events, sizeof(struct net_event), 0);
    if (!evt)
        return 0;

    __builtin_memset(evt, 0, sizeof(struct net_event));
    fill_process_info(evt);

    if (should_filter(evt->uid)) {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    evt->event_type = EVENT_TCP_CLOSE;
    evt->protocol   = IPPROTO_TCP;

    // 判断地址族
    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    evt->addr_family = family;

    if (family == AF_INET) {
        evt->ip_version = 4;
        BPF_CORE_READ_INTO(&evt->dst_addr_v4, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&evt->src_addr_v4, sk, __sk_common.skc_rcv_saddr);
    } else if (family == AF_INET6) {
        evt->ip_version = 6;
        BPF_CORE_READ_INTO(&evt->dst_addr_v6, sk, __sk_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&evt->src_addr_v6, sk, __sk_common.skc_v6_rcv_saddr);
    } else {
        bpf_ringbuf_discard(evt, 0);
        return 0;
    }

    __u16 dport = 0;
    BPF_CORE_READ_INTO(&dport, sk, __sk_common.skc_dport);
    evt->dst_port = bpf_ntohs(dport);

    __u16 sport = 0;
    BPF_CORE_READ_INTO(&sport, sk, __sk_common.skc_num);
    evt->src_port = sport;

    // 读取发送字节数
    BPF_CORE_READ_INTO(&evt->bytes_sent, sk, sk_wmem_queued);

    bpf_ringbuf_submit(evt, 0);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";
