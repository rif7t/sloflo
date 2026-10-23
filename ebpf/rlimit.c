#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

#define ETH_P_IP 0x0800
#define TARGET_PORT 8080

// Local address (network byte order) of the server being protected; 0 = any.
// Other services on the host may also listen on TARGET_PORT (e.g. health
// endpoints), and their traffic must not be measured or policed.
volatile const __u32 target_addr = 0;

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
    __uint(max_entries, 65536);
    __type(key, struct sock*);
    __type(value, u64);
} req_start SEC(".maps");  // sock -> time (ns) its pending request arrived

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

// A request is "inflight" from the moment its payload reaches the server socket
// until the server's first write back (or the socket closes unanswered).
// inflight_total counts those requests; latency is arrival -> first write.
static __always_inline bool is_target(struct sock *sk)
{
    if (BPF_CORE_READ(sk, __sk_common.skc_num) != TARGET_PORT)
        return false;
    return !target_addr || BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr) == target_addr;
}

static __always_inline void inflight_add(int n)
{
    u32 zero = 0;
    u64 *total = bpf_map_lookup_elem(&inflight_total, &zero);
    if (!total)
        return;
    if (n > 0)
        __sync_fetch_and_add(total, n);
    else
        __sync_fetch_and_sub(total, -n);
}

SEC("fentry/tcp_rcv_established")
int BPF_PROG(fentry_tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {

    if (!is_target(sk))
        return 0;

    // only a segment that carries payload starts a request
    struct tcphdr th;
    if (bpf_probe_read_kernel(&th, sizeof(th), BPF_CORE_READ(skb, data)))
        return 0;
    if (BPF_CORE_READ(skb, len) <= (u32)th.doff * 4)
        return 0;

    // NOEXIST: later segments of a request already pending keep the first time
    u64 now = bpf_ktime_get_ns();
    if (bpf_map_update_elem(&req_start, &sk, &now, BPF_NOEXIST))
        return 0;
    inflight_add(1);
    return 0;
}

SEC("fentry/tcp_sendmsg")
int BPF_PROG(fentry_tcp_sendmsg, struct sock *sk) {

    if (!is_target(sk))
        return 0;

    u64 *start = bpf_map_lookup_elem(&req_start, &sk);
    if (!start)
        return 0;
    u64 latency = bpf_ktime_get_ns() - *start;
    if (bpf_map_delete_elem(&req_start, &sk))
        return 0;
    inflight_add(-1);

    u64 *evt = bpf_ringbuf_reserve(&latency_events, sizeof(*evt), 0);
    if (!evt)
        return 0;
    *evt = latency;
    bpf_ringbuf_submit(evt, 0);
    return 0;
}

SEC("fentry/tcp_set_state")
int BPF_PROG(fentry_tcp_set_state, struct sock *sk, int state)
{
    if (state != TCP_CLOSE)
        return 0;
    if (!is_target(sk))
        return 0;

    // closed with a request still unanswered
    if (!bpf_map_delete_elem(&req_start, &sk))
        inflight_add(-1);
    return 0;
}


SEC("xdp")
int xdp_rate_limiter(struct xdp_md *ctx) {
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;

    // only police IPv4 TCP traffic destined for the server port
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return XDP_PASS;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return XDP_PASS;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return XDP_PASS;
    if (ip->protocol != IPPROTO_TCP)
        return XDP_PASS;

    struct tcphdr *tcp = (void *)ip + ip->ihl * 4;
    if ((void *)(tcp + 1) > data_end)
        return XDP_PASS;
    if (bpf_ntohs(tcp->dest) != TARGET_PORT)
        return XDP_PASS;
    if (target_addr && ip->daddr != target_addr)
        return XDP_PASS;

    // only shed new connections; ACK/FIN/data for established flows must get
    // through so inflight can drain
    if (!(tcp->syn && !tcp->ack))
        return XDP_PASS;

    u32 zero = 0;
    struct control_state *cs = bpf_map_lookup_elem(&control_map, &zero);
    u64 *inflight = bpf_map_lookup_elem(&inflight_total, &zero);
    if (!cs || !inflight)
        return XDP_PASS;

    // compare against the live count, not cs->inflight: that copy is only
    // refreshed once per control tick, so a burst of SYNs inside one tick would
    // all see a stale value and pass
    // limit stays 0 until the controller's first tick; treat that as unset
    if (cs->concurrency_limit && *inflight > cs->concurrency_limit) {
        bpf_printk("DROPPED: inflight=%llu, limit=%d", *inflight, cs->concurrency_limit);
        return XDP_DROP;
    }
    return XDP_PASS;
}

char LICENSE[] SEC("license") = "GPL";
