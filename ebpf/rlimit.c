#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define STALL_NS (5ULL * 1000 * 1000 * 1000) // 5 seconds


struct sock_state{
    __u64 last_progress_ns;
    __u8 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, __u64);              
    __type(value, struct sock_state);
} sock_states SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, __u32);
    __type(value, __s64);
} active_count SEC(".maps");

struct control_state{
    u64 min_rtt_ns;
    u32 concurrency_limit;
    u32 inflight;
    u64 latest_rtt_ns;
    u64 last_progress_ns;
    u8 active;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 65536);
    __type(key, struct sock *);
    __type(value, struct control_state);
} sock_to_cs SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __type(key, u32);
    __type(value, struct control_state);
    __uint(max_entries, 1);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 12);
} latency_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);  
    __type(value, u32); 
} xdp_rate_limit_map SEC(".maps");

static __always_inline u64 pid_tid_key(u32 pid, u32 tid) {
    return ((u64)pid << 32) | tid;
}

static __always_inline void decay_if_stalled(struct control_state *cs, __u64 now)
{
    if(!cs || !cs->active)
        return;
    
     if (now - cs->last_progress_ns > STALL_NS) { 
        if (cs->inflight > 0)
            __sync_fetch_and_add(&cs->inflight, -1);

        cs->active = 0;
    }
}

static __always_inline void mark_active(struct control_state *cs, __u64 now)
{
   if (!cs)
        return;
    decay_if_stalled(cs, now);

    if (!cs->active) {
        __sync_fetch_and_add(&cs->inflight, 1);
        cs->active = 1;
    }

    cs->last_progress_ns = now;
}

// SEC("kprobe/tcp_rcv_established")
// int BPF_PROG(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
// struct control_state *cs = bpf_map_lookup_elem(&sock_to_cs, &sk);
//     if (!cs)
//         return 0;

//     mark_active(cs, bpf_ktime_get_ns());

//     u64 rtt;
//     struct tcp_sock *ts = (struct tcp_sock *)(sk);
//     rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
//     rtt *= 1000;
//     if(rtt == 0)
//         return 0;
//     u64 *evt = bpf_ringbuf_reserve(&latency_events, sizeof(*evt), 0);
//     if(!evt)
//         return 0;
//     if(evt){
//         *evt = rtt;
//         bpf_printk("rtt event: %d", rtt);
//         bpf_ringbuf_submit(evt, 0);
//     }    
   
//     return 0;
// }

SEC("kprobe/tcp_rcv_established")
int BPF_PROG(kprobe_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
struct control_state *cs = bpf_map_lookup_elem(&sock_to_cs, &sk);
    if (!cs)
        return 0;

    mark_active(cs, bpf_ktime_get_ns());

    u64 rtt;
    struct tcp_sock *ts = (struct tcp_sock *)(sk);
    rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    rtt *= 1000;
    if(rtt == 0)
        return 0;
    u64 *evt = bpf_ringbuf_reserve(&latency_events, sizeof(*evt), 0);
    if(!evt)
        return 0;
    if(evt){
        *evt = rtt;
        bpf_printk("rtt event: %d", rtt);
        bpf_ringbuf_submit(evt, 0);
    }
   
    return 0;
}

SEC("kretprobe/tcp_sendmsg")
int BPF_PROG(kretprobe_tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size, int ret) {
    struct control_state *cs = bpf_map_lookup_elem(&sock_to_cs, &sk);

    if (!cs) {
        struct control_state init = {
            .concurrency_limit = 10, 
            .inflight = 0,
            .active = 0,
        };
        bpf_map_update_elem(&sock_to_cs, &sk, &init, BPF_NOEXIST);

        cs = bpf_map_lookup_elem(&sock_to_cs, &sk);
        if (!cs)
            return 0;
    }

    mark_active(cs, bpf_ktime_get_ns());
    return 0;
}


// SEC("kprobe/tcp_retransmit_skb")
// int BPF_PROG(kprobe_tcp_retransmit_skb, struct sock *sk, struct sk_buff *skb)
// {
//    struct control_state *cs = bpf_map_lookup_elem(&sock_to_cs, &sk);
//     if (!cs)
//         return 0;

//     decay_if_stalled(cs, bpf_ktime_get_ns());
//     return 0;
// }

SEC("kprobe/tcp_close")
int BPF_PROG(kprobe_tcp_close, struct sock *sk)
{
    struct control_state *cs;

    cs = bpf_map_lookup_elem(&sock_to_cs, &sk);
    if (!cs)
        return 0;

    if (cs->active){
        if (cs->inflight > 0)
    __sync_fetch_and_add(&cs->inflight, -1);

    }

    bpf_map_delete_elem(&sock_to_cs, &sk);
    return 0;
}

SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx) {
    u32 zero = 0;
    struct control_state *cs = bpf_map_lookup_elem(&control_map, &zero);
    if(!cs) 
        return XDP_PASS;
    if(cs->inflight >= cs->concurrency_limit){
        bpf_printk("DROPPED");
        //return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
