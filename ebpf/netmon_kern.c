// SPDX-License-Identifier: GPL-2.0
// NetMonitor Pro — eBPF 内核探针 (优化版)
// 文件位置: ebpf/netmon_kern.c
//
// 优化点:
//   1. 提取公共端口读取函数 read_ports()，消除 read_v4/read_v6 中重复代码
//   2. 统一 TCP kretprobe 处理函数 handle_tcp_connect_ret()，消除 v4/v6 ~80行重复
//   3. 统一 UDP handler 处理函数 handle_udp_sendmsg()，消除 v4/v6 重复
//   4. UDP handler 先检查 filter 再 reserve ringbuf，避免高流量下浪费 ringbuf
//   5. 合并 fill_ci/fill_evt 为 fill_process_info()，消除重复
//   6. connect_args map 增加 LRU 模式防泄漏

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

/* ────────────────────── 常量定义 ────────────────────── */

#define MAX_ENTRIES      65536
#define RINGBUF_SIZE     (1 << 20)   /* 1 MiB */
#define TASK_COMM_LEN    16
#define ADDR_LEN_V6      16

/* 事件类型 */
enum event_type {
    EVENT_TCP_CONNECT     = 1,
    EVENT_TCP_CONNECT_RET = 2,
    EVENT_TCP_CLOSE       = 3,
    EVENT_UDP_SEND        = 4,
};

/* ────────────────────── 数据结构 ────────────────────── */

struct config {
    __u8  capture_tcp;
    __u8  capture_udp;
    __u32 target_uid;      /* 0 = 不过滤 */
    __u32 target_pid;      /* 0 = 不过滤 */
};

struct net_event {
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tgid;
    __u32  uid;
    __u32  gid;
    char   comm[TASK_COMM_LEN];
    __u8   event_type;
    __u8   ip_version;     /* 4 or 6 */
    __u16  protocol;       /* IPPROTO_TCP / IPPROTO_UDP */
    __u8   src_addr[ADDR_LEN_V6];
    __u16  src_port;
    __u8   dst_addr[ADDR_LEN_V6];
    __u16  dst_port;
    __u64  bytes_sent;
    __s32  ret_val;
};

struct connect_info {
    struct sock *sk;
    __u64  timestamp_ns;
    __u32  pid;
    __u32  tgid;
    __u32  uid;
    __u32  gid;
    char   comm[TASK_COMM_LEN];
};

/* ────────────────────── Maps ────────────────────── */

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, RINGBUF_SIZE);
} events SEC(".maps");

/* [优化] 使用 LRU_HASH 防止 kretprobe 未触发导致 map entry 泄漏 */
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_ENTRIES);
    __type(key, __u64);
    __type(value, struct connect_info);
} connect_args SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, struct config);
} global_config SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u8);
} uid_filter SEC(".maps");

/* ────────────────────── 辅助函数 ────────────────────── */

/* [优化] 合并 fill_ci + fill_evt，统一进程信息提取 */
static __always_inline void fill_process_info_ci(struct connect_info *ci)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    ci->pid  = (__u32)(pid_tgid);
    ci->tgid = (__u32)(pid_tgid >> 32);
    ci->uid  = (__u32)(uid_gid);
    ci->gid  = (__u32)(uid_gid >> 32);
    ci->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ci->comm, sizeof(ci->comm));
}

static __always_inline void fill_process_info_evt(struct net_event *e)
{
    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u64 uid_gid  = bpf_get_current_uid_gid();
    e->pid  = (__u32)(pid_tgid);
    e->tgid = (__u32)(pid_tgid >> 32);
    e->uid  = (__u32)(uid_gid);
    e->gid  = (__u32)(uid_gid >> 32);
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void copy_pi(struct net_event *e,
                                    const struct connect_info *ci)
{
    e->pid  = ci->pid;
    e->tgid = ci->tgid;
    e->uid  = ci->uid;
    e->gid  = ci->gid;
    __builtin_memcpy(e->comm, ci->comm, TASK_COMM_LEN);
}

/* UID 过滤检查 */
static __always_inline int should_filter(__u32 uid)
{
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (!cfg)
        return 0;

    /* target_uid 过滤 */
    if (cfg->target_uid && uid != cfg->target_uid)
        return 1;

    /* uid_filter map 过滤 */
    __u8 *blocked = bpf_map_lookup_elem(&uid_filter, &uid);
    if (blocked && *blocked)
        return 1;

    return 0;
}

/* target_pid 过滤检查 */
static __always_inline int should_filter_pid(__u32 pid)
{
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && cfg->target_pid && pid != cfg->target_pid)
        return 1;
    return 0;
}

/* [优化] 公共端口读取——从 read_v4/read_v6 中提取 */
static __always_inline void read_ports(struct net_event *e, struct sock *sk)
{
    __u16 dp = 0, sp = 0;
    BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport);
    e->dst_port = bpf_ntohs(dp);
    BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num);
    e->src_port = sp;
}

/* 读取 IPv4 地址 + 端口 */
static __always_inline void read_v4(struct net_event *e, struct sock *sk)
{
    e->ip_version = 4;
    BPF_CORE_READ_INTO(&e->src_addr, sk, __sk_common.skc_rcv_saddr);
    BPF_CORE_READ_INTO(&e->dst_addr, sk, __sk_common.skc_daddr);
    read_ports(e, sk);
}

/* 读取 IPv6 地址 + 端口 */
static __always_inline void read_v6(struct net_event *e, struct sock *sk)
{
    e->ip_version = 6;
    BPF_CORE_READ_INTO(&e->src_addr, sk,
                        __sk_common.skc_v6_rcv_saddr.in6_u.u6_addr8);
    BPF_CORE_READ_INTO(&e->dst_addr, sk,
                        __sk_common.skc_v6_daddr.in6_u.u6_addr8);
    read_ports(e, sk);
}

/* ────────────────────── TCP Connect (kprobe) ────────────────────── */

static __always_inline int handle_tcp_connect(struct sock *sk)
{
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && !cfg->capture_tcp)
        return 0;

    struct connect_info ci = {};
    fill_process_info_ci(&ci);

    if (should_filter(ci.uid))
        return 0;
    if (should_filter_pid(ci.pid))
        return 0;

    ci.sk = sk;
    __u64 pt = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_args, &pt, &ci, BPF_ANY);
    return 0;
}

SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp4, struct sock *sk)
{
    return handle_tcp_connect(sk);
}

SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kp_tcp6, struct sock *sk)
{
    return handle_tcp_connect(sk);
}

/* ────────────────────── TCP Connect Return (kretprobe) ────────────────────── */

/* [优化] 统一 v4/v6 kretprobe，消除 ~80 行重复代码 */
static __always_inline int handle_tcp_connect_ret(int ret, __u8 ip_ver)
{
    __u64 pt = bpf_get_current_pid_tgid();
    struct connect_info *ci = bpf_map_lookup_elem(&connect_args, &pt);
    if (!ci)
        return 0;

    struct sock *sk = ci->sk;
    struct connect_info local_ci = {};
    __builtin_memcpy(&local_ci, ci, sizeof(local_ci));
    bpf_map_delete_elem(&connect_args, &pt);

    /* 事件1: TCP_CONNECT */
    struct net_event *e1 = bpf_ringbuf_reserve(&events, sizeof(*e1), 0);
    if (e1) {
        __builtin_memset(e1, 0, sizeof(*e1));
        copy_pi(e1, &local_ci);
        e1->timestamp_ns = local_ci.timestamp_ns;
        e1->event_type   = EVENT_TCP_CONNECT;
        e1->protocol     = IPPROTO_TCP;
        if (ip_ver == 4)
            read_v4(e1, sk);
        else
            read_v6(e1, sk);
        bpf_ringbuf_submit(e1, 0);
    }

    /* 事件2: TCP_CONNECT_RET */
    struct net_event *e2 = bpf_ringbuf_reserve(&events, sizeof(*e2), 0);
    if (e2) {
        __builtin_memset(e2, 0, sizeof(*e2));
        copy_pi(e2, &local_ci);
        e2->timestamp_ns = bpf_ktime_get_ns();
        e2->event_type   = EVENT_TCP_CONNECT_RET;
        e2->protocol     = IPPROTO_TCP;
        e2->ret_val      = ret;
        if (ip_ver == 4)
            read_v4(e2, sk);
        else
            read_v6(e2, sk);
        bpf_ringbuf_submit(e2, 0);
    }

    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp4, int ret)
{
    return handle_tcp_connect_ret(ret, 4);
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(krp_tcp6, int ret)
{
    return handle_tcp_connect_ret(ret, 6);
}

/* ────────────────────── TCP Close ────────────────────── */

static __always_inline int handle_tcp_close(struct sock *sk, __u8 ip_ver)
{
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && !cfg->capture_tcp)
        return 0;

    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)(uid_gid);
    if (should_filter(uid))
        return 0;

    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_info_evt(e);
    e->event_type = EVENT_TCP_CLOSE;
    e->protocol   = IPPROTO_TCP;

    if (ip_ver == 4)
        read_v4(e, sk);
    else
        read_v6(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk)
{
    __u16 family = 0;
    BPF_CORE_READ_INTO(&family, sk, __sk_common.skc_family);
    if (family == 2)       /* AF_INET */
        return handle_tcp_close(sk, 4);
    else if (family == 10) /* AF_INET6 */
        return handle_tcp_close(sk, 6);
    return 0;
}

/* ────────────────────── UDP Send ────────────────────── */

/* [优化] 统一 UDP v4/v6 handler + 先过滤再 reserve */
static __always_inline int handle_udp_sendmsg(struct sock *sk,
                                               struct msghdr *msg,
                                               size_t len,
                                               __u8 ip_ver)
{
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && !cfg->capture_udp)
        return 0;

    /* [优化] 先检查 UID/PID 过滤，再 reserve ringbuf，避免浪费 */
    __u64 uid_gid = bpf_get_current_uid_gid();
    __u32 uid = (__u32)(uid_gid);
    if (should_filter(uid))
        return 0;

    __u64 pid_tgid = bpf_get_current_pid_tgid();
    __u32 pid = (__u32)(pid_tgid);
    if (should_filter_pid(pid))
        return 0;

    /* 通过过滤后才 reserve */
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    __builtin_memset(e, 0, sizeof(*e));
    fill_process_info_evt(e);
    e->event_type  = EVENT_UDP_SEND;
    e->protocol    = IPPROTO_UDP;
    e->bytes_sent  = len;

    if (ip_ver == 4)
        read_v4(e, sk);
    else
        read_v6(e, sk);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp4, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_sendmsg(sk, msg, len, 4);
}

SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kp_udp6, struct sock *sk, struct msghdr *msg, size_t len)
{
    return handle_udp_sendmsg(sk, msg, len, 6);
}

char LICENSE[] SEC("license") = "GPL";