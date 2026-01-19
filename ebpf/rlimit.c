#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define SERVER_PID 278040
#define TARGET_PORT 8080

struct control_state {
	u64 min_rtt_ns;
	u32 concurrency_limit;
	u32 inflight;
	u64 latest_rtt_ns;
    u64 window_min_rtt_ns;
    u64 window_start_ns;
};

struct {
	__uint(type, BPF_MAP_TYPE_ARRAY);
	__type(key, u32);
	__type(value, struct control_state);
	__uint(max_entries, 1);
} control_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct sock*);
    __type(value, u64);
} sock_inflight SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} inflight_total SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 1 << 12);
} latency_events SEC(".maps");

static __always_inline unsigned int tcp_left_out(const struct tcp_sock *tp)
{
    u32 sacked = BPF_CORE_READ(tp, sacked_out);
    u32 lost   = BPF_CORE_READ(tp, lost_out);
    return sacked + lost;
}

static __always_inline unsigned int tcp_packets_in_flight(const struct tcp_sock *tp)
{
    u32 packets_out  = BPF_CORE_READ(tp, packets_out);
    u32 retrans_out  = BPF_CORE_READ(tp, retrans_out);
    return packets_out - tcp_left_out(tp) + retrans_out;
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(fentry_tcp_rcv_established, struct sock *sk) {

    //manually filter http packets
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != SERVER_PID){
        return 0;
    }
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sport != TARGET_PORT)
        return 0;
    u64 rtt;
    struct tcp_sock *ts = (struct tcp_sock *)(sk);
    u64 cur = tcp_packets_in_flight(ts);
    u64 *prev = bpf_map_lookup_elem(&sock_inflight, &sk);
    s32 delta;
    
    if(prev){
        if(cur == *prev)
            return 0;
        delta = (s32)cur - (s32)(*prev);
        *prev = cur;
    }else{
        bpf_map_update_elem(&sock_inflight, &sk, &cur, BPF_ANY);
        delta = cur;
    }
    u32 zero = 0;
    u64 *total = bpf_map_lookup_elem(&inflight_total, &zero);
    if(total){
        if (delta > 0)
            __sync_fetch_and_add(total, delta);
        else if (delta < 0){
            __sync_fetch_and_sub(total, -delta);
        }
            
    }
    rtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    rtt *= 1000;    
    if (rtt == 0)
        return 0;
    
    u64 *evt = bpf_ringbuf_reserve(&latency_events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    
    *evt = rtt;
    bpf_ringbuf_submit(evt, 0);
    
    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(fentry_tcp_set_state, struct sock *sk, int state)
{
    //manually filter http server 
    u64 pid = bpf_get_current_pid_tgid() >> 32;
    if (pid != SERVER_PID){
        return 0;
    }
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    if (sport != TARGET_PORT)
        return 0;
    u64 rtt;
    struct tcp_sock *ts = (struct tcp_sock *)(sk);
    u64 cur = tcp_packets_in_flight(ts);
    u64 *prev = bpf_map_lookup_elem(&sock_inflight, &sk);
    s32 delta;
    
    if(prev){
        if(cur == *prev)
            return 0;
        delta = (s32)cur - (s32)(*prev);
        *prev = cur;
    }else{
        bpf_map_update_elem(&sock_inflight, &sk, &cur, BPF_ANY);
        delta = cur;
    }
    u32 zero = 0;
    u64 *total = bpf_map_lookup_elem(&inflight_total, &zero);
    if(total){
        if (delta > 0)
            __sync_fetch_and_add(total, delta);
        else if (delta < 0){
            __sync_fetch_and_sub(total, -delta);
        }
    }
    return 0;
}


SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx) {
      u64 pid = bpf_get_current_pid_tgid() >> 32;

    //manually filter http server packets
    if (pid != SERVER_PID){
        return 0;
    }
    u32 zero = 0;
    u32 *inflight = bpf_map_lookup_elem(&inflight_total, &zero);
    struct control_state *cs = bpf_map_lookup_elem(&control_map, &zero);
    if (!cs)
        return XDP_PASS;

    if (cs->inflight > cs->concurrency_limit) {
        bpf_printk("DROPPED: inflight=%d, limit=%d", cs->inflight, cs->concurrency_limit);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
