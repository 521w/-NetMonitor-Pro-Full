// SPDX-License-Identifier: GPL-2.0
// NetMonitor Pro — eBPF（致命级修复版）
// [FIX-#2] pid/tgid修正 [FIX-#5] kretprobe读地址 [FIX-#12] 补发TCP_CONNECT

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

enum event_type {
    EVENT_TCP_CONNECT = 1,
    EVENT_TCP_CONNECT_RET,
    EVENT_UDP_SEND,
    EVENT_TCP_CLOSE,
    EVENT_DNS_QUERY,
};

struct in6_addr_t { __u8 addr[16]; };

struct net_event {
    __u64 timestamp_ns;
    __u32 event_type;
    __u32 pid;       // 线程ID (低32位)
    __u32 tgid;      // 进程ID (高32位)
    __u32 uid;
    __u32 gid;
    char  comm[TASK_COMM_LEN];
    __u8  ip_version;
    __u8  protocol;
    __u16 src_port;
    __u16 dst_port;
    __u32 src_addr_v4;
    __u32 dst_addr_v4;
    struct in6_addr_t src_addr_v6;
    struct in6_addr_t dst_addr_v6;
    __u64 bytes_sent;
    __s32 ret_val;
    __u16 addr_family;
    __u16 _pad;
};

// [FIX-#5] 只存sk指针+进程信息，kretprobe再读地址
struct connect_info {
    struct sock *sk;
    __u64 timestamp_ns;
    __u32 pid;
    __u32 tgid;
    __u32 uid;
    __u32 gid;
    __u8  ip_version;
    __u8  _pad[3];
    char  comm[TASK_COMM_LEN];
};

struct { __uint(type, BPF_MAP_TYPE_RINGBUF); __uint(max_entries, 1 << 24); } events SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 65536); __type(key, __u64); __type(value, struct connect_info); } connect_args SEC(".maps");
struct { __uint(type, BPF_MAP_TYPE_HASH); __uint(max_entries, 256); __type(key, __u32); __type(value, __u8); } uid_filter SEC(".maps");
struct config { __u8 filter_enabled; __u8 capture_udp; __u16 _pad; };
struct { __uint(type, BPF_MAP_TYPE_ARRAY); __uint(max_entries, 1); __type(key, __u32); __type(value, struct config); } global_config SEC(".maps");

static __always_inline int should_filter(__u32 uid) {
    __u32 key = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &key);
    if (!cfg || !cfg->filter_enabled) return 0;
    __u8 *val = bpf_map_lookup_elem(&uid_filter, &uid);
    return val ? 0 : 1;
}

// [FIX-#2] 高32=tgid(进程ID), 低32=pid(线程ID)
static __always_inline void fill_ci(struct connect_info *ci) {
    __u64 pt = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();
    ci->tgid = (__u32)(pt >> 32);
    ci->pid  = (__u32)(pt);
    ci->uid  = (__u32)(ug);
    ci->gid  = (__u32)(ug >> 32);
    ci->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&ci->comm, sizeof(ci->comm));
}

static __always_inline void fill_evt(struct net_event *e) {
    __u64 pt = bpf_get_current_pid_tgid();
    __u64 ug = bpf_get_current_uid_gid();
    e->tgid = (__u32)(pt >> 32);
    e->pid  = (__u32)(pt);
    e->uid  = (__u32)(ug);
    e->gid  = (__u32)(ug >> 32);
    e->timestamp_ns = bpf_ktime_get_ns();
    bpf_get_current_comm(&e->comm, sizeof(e->comm));
}

static __always_inline void copy_pi(struct net_event *e, struct connect_info *c) {
    e->pid = c->pid; e->tgid = c->tgid; e->uid = c->uid; e->gid = c->gid;
    __builtin_memcpy(e->comm, c->comm, TASK_COMM_LEN);
}

// [FIX-#5] kretprobe时从sk读地址（此时内核已完成赋值）
static __always_inline void read_v4(struct net_event *e, struct sock *sk) {
    e->ip_version = 4; e->protocol = IPPROTO_TCP; e->addr_family = AF_INET;
    BPF_CORE_READ_INTO(&e->dst_addr_v4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e->src_addr_v4, sk, __sk_common.skc_rcv_saddr);
    __u16 dp = 0; BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport); e->dst_port = bpf_ntohs(dp);
    __u16 sp = 0; BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num); e->src_port = sp;
}

static __always_inline void read_v6(struct net_event *e, struct sock *sk) {
    e->ip_version = 6; e->protocol = IPPROTO_TCP; e->addr_family = AF_INET6;
    BPF_CORE_READ_INTO(&e->dst_addr_v6, sk, __sk_common.skc_v6_daddr);
    BPF_CORE_READ_INTO(&e->src_addr_v6, sk, __sk_common.skc_v6_rcv_saddr);
    __u16 dp = 0; BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport); e->dst_port = bpf_ntohs(dp);
    __u16 sp = 0; BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num); e->src_port = sp;
}

// ═══ TCP v4 ═══
SEC("kprobe/tcp_v4_connect")
int BPF_KPROBE(kp_tcp4, struct sock *sk) {
    struct connect_info ci = {};
    fill_ci(&ci);
    if (should_filter(ci.uid)) return 0;
    ci.sk = sk; ci.ip_version = 4;
    __u64 pt = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_args, &pt, &ci, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v4_connect")
int BPF_KRETPROBE(krp_tcp4, int ret) {
    __u64 pt = bpf_get_current_pid_tgid();
    struct connect_info *ci = bpf_map_lookup_elem(&connect_args, &pt);
    if (!ci) return 0;
    struct sock *sk = ci->sk;
    struct connect_info cc = {}; __builtin_memcpy(&cc, ci, sizeof(cc));
    bpf_map_delete_elem(&connect_args, &pt);

    // [FIX-#12] 事件1: TCP_CONNECT
    struct net_event *e1 = bpf_ringbuf_reserve(&events, sizeof(*e1), 0);
    if (e1) {
        __builtin_memset(e1, 0, sizeof(*e1));
        copy_pi(e1, &cc); e1->timestamp_ns = cc.timestamp_ns;
        e1->event_type = EVENT_TCP_CONNECT;
        read_v4(e1, sk); bpf_ringbuf_submit(e1, 0);
    }
    // [FIX-#12] 事件2: TCP_CONNECT_RET
    struct net_event *e2 = bpf_ringbuf_reserve(&events, sizeof(*e2), 0);
    if (e2) {
        __builtin_memset(e2, 0, sizeof(*e2));
        copy_pi(e2, &cc); e2->timestamp_ns = bpf_ktime_get_ns();
        e2->event_type = EVENT_TCP_CONNECT_RET; e2->ret_val = ret;
        read_v4(e2, sk); bpf_ringbuf_submit(e2, 0);
    }
    return 0;
}

// ═══ TCP v6 ═══
SEC("kprobe/tcp_v6_connect")
int BPF_KPROBE(kp_tcp6, struct sock *sk) {
    struct connect_info ci = {};
    fill_ci(&ci);
    if (should_filter(ci.uid)) return 0;
    ci.sk = sk; ci.ip_version = 6;
    __u64 pt = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&connect_args, &pt, &ci, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_v6_connect")
int BPF_KRETPROBE(krp_tcp6, int ret) {
    __u64 pt = bpf_get_current_pid_tgid();
    struct connect_info *ci = bpf_map_lookup_elem(&connect_args, &pt);
    if (!ci) return 0;
    struct sock *sk = ci->sk;
    struct connect_info cc = {}; __builtin_memcpy(&cc, ci, sizeof(cc));
    bpf_map_delete_elem(&connect_args, &pt);

    struct net_event *e1 = bpf_ringbuf_reserve(&events, sizeof(*e1), 0);
    if (e1) {
        __builtin_memset(e1, 0, sizeof(*e1));
        copy_pi(e1, &cc); e1->timestamp_ns = cc.timestamp_ns;
        e1->event_type = EVENT_TCP_CONNECT; read_v6(e1, sk);
        bpf_ringbuf_submit(e1, 0);
    }
    struct net_event *e2 = bpf_ringbuf_reserve(&events, sizeof(*e2), 0);
    if (e2) {
        __builtin_memset(e2, 0, sizeof(*e2));
        copy_pi(e2, &cc); e2->timestamp_ns = bpf_ktime_get_ns();
        e2->event_type = EVENT_TCP_CONNECT_RET; e2->ret_val = ret;
        read_v6(e2, sk); bpf_ringbuf_submit(e2, 0);
    }
    return 0;
}

// ═══ UDP v4 ═══
SEC("kprobe/udp_sendmsg")
int BPF_KPROBE(kp_udp4, struct sock *sk, struct msghdr *msg, size_t len) {
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && !cfg->capture_udp) return 0;
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e)); fill_evt(e);
    if (should_filter(e->uid)) { bpf_ringbuf_discard(e, 0); return 0; }
    e->event_type = EVENT_UDP_SEND; e->ip_version = 4;
    e->protocol = IPPROTO_UDP; e->addr_family = AF_INET; e->bytes_sent = (__u64)len;
    BPF_CORE_READ_INTO(&e->dst_addr_v4, sk, __sk_common.skc_daddr);
    BPF_CORE_READ_INTO(&e->src_addr_v4, sk, __sk_common.skc_rcv_saddr);
    __u16 dp = 0; BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport); e->dst_port = bpf_ntohs(dp);
    __u16 sp = 0; BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num); e->src_port = sp;
    if (e->dst_port == 53) e->event_type = EVENT_DNS_QUERY;
    bpf_ringbuf_submit(e, 0); return 0;
}

// ═══ UDP v6 ═══
SEC("kprobe/udpv6_sendmsg")
int BPF_KPROBE(kp_udp6, struct sock *sk, struct msghdr *msg, size_t len) {
    __u32 k = 0;
    struct config *cfg = bpf_map_lookup_elem(&global_config, &k);
    if (cfg && !cfg->capture_udp) return 0;
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e)); fill_evt(e);
    if (should_filter(e->uid)) { bpf_ringbuf_discard(e, 0); return 0; }
    e->event_type = EVENT_UDP_SEND; e->ip_version = 6;
    e->protocol = IPPROTO_UDP; e->addr_family = AF_INET6; e->bytes_sent = (__u64)len;
    BPF_CORE_READ_INTO(&e->dst_addr_v6, sk, __sk_common.skc_v6_daddr);
    BPF_CORE_READ_INTO(&e->src_addr_v6, sk, __sk_common.skc_v6_rcv_saddr);
    __u16 dp = 0; BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport); e->dst_port = bpf_ntohs(dp);
    __u16 sp = 0; BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num); e->src_port = sp;
    if (e->dst_port == 53) e->event_type = EVENT_DNS_QUERY;
    bpf_ringbuf_submit(e, 0); return 0;
}

// ═══ TCP CLOSE ═══
SEC("kprobe/tcp_close")
int BPF_KPROBE(kp_tcp_close, struct sock *sk) {
    struct net_event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e) return 0;
    __builtin_memset(e, 0, sizeof(*e)); fill_evt(e);
    if (should_filter(e->uid)) { bpf_ringbuf_discard(e, 0); return 0; }
    e->event_type = EVENT_TCP_CLOSE; e->protocol = IPPROTO_TCP;
    __u16 fam = 0; BPF_CORE_READ_INTO(&fam, sk, __sk_common.skc_family); e->addr_family = fam;
    if (fam == AF_INET) {
        e->ip_version = 4;
        BPF_CORE_READ_INTO(&e->dst_addr_v4, sk, __sk_common.skc_daddr);
        BPF_CORE_READ_INTO(&e->src_addr_v4, sk, __sk_common.skc_rcv_saddr);
    } else if (fam == AF_INET6) {
        e->ip_version = 6;
        BPF_CORE_READ_INTO(&e->dst_addr_v6, sk, __sk_common.skc_v6_daddr);
        BPF_CORE_READ_INTO(&e->src_addr_v6, sk, __sk_common.skc_v6_rcv_saddr);
    } else { bpf_ringbuf_discard(e, 0); return 0; }
    __u16 dp = 0; BPF_CORE_READ_INTO(&dp, sk, __sk_common.skc_dport); e->dst_port = bpf_ntohs(dp);
    __u16 sp = 0; BPF_CORE_READ_INTO(&sp, sk, __sk_common.skc_num); e->src_port = sp;
    BPF_CORE_READ_INTO(&e->bytes_sent, sk, sk_wmem_queued);
    bpf_ringbuf_submit(e, 0); return 0;
}

char LICENSE[] SEC("license") = "GPL";