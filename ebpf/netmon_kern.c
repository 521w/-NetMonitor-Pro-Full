#include "vmlinux.h"
#include <bpf/bpf_helpers.h>

struct event_t {
    u32 pid;
    u32 uid;
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

SEC("kprobe/tcp_v4_connect")
int kprobe(struct pt_regs *ctx){
    struct event_t *e = bpf_ringbuf_reserve(&events,sizeof(*e),0);
    if(!e) return 0;

    e->pid = bpf_get_current_pid_tgid()>>32;
    e->uid = bpf_get_current_uid_gid();

    bpf_ringbuf_submit(e,0);
    return 0;
}

char LICENSE[] SEC("license")="GPL";
