#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_CAPTURE_LEN 4096
#define ETH_P_IP        0x0800
#define TC_ACT_OK       0
#define TC_ACT_SHOT     2

struct event {
    u64 ts;
    u64 conn_id;
    u32 pid;
    u32 len;
    u8 dir;
    u8 truncated;
    char comm[16];
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    char data[MAX_CAPTURE_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

struct recv_ctx {
    void *ubuf;
    u64 conn_id;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u64);
    __type(value, struct recv_ctx);
} recv_bufs SEC(".maps");

/* normalized 4-tuple: either packet direction of a flow hashes to the
 * same key, so one block entry covers both directions */
struct flow_key {
    u32 addr_lo;
    u32 addr_hi;
    u16 port_lo;
    u16 port_hi;
};

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, struct flow_key);
    __type(value, u64);
} blocklist SEC(".maps");

static __always_inline void make_flow_key(struct flow_key *k,
    u32 a1, u32 a2, u16 p1, u16 p2)
{
    if (a1 < a2 || (a1 == a2 && p1 < p2)) {
        k->addr_lo = a1; k->addr_hi = a2;
        k->port_lo = p1; k->port_hi = p2;
    } else {
        k->addr_lo = a2; k->addr_hi = a1;
        k->port_lo = p2; k->port_hi = p1;
    }
}

SEC("kprobe/tcp_sendmsg_locked")
int BPF_KPROBE(api_sentinel, struct sock *sk, struct msghdr *msg, size_t size)
{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (__builtin_memcmp(comm, "uvicorn", 7) != 0)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->conn_id = (u64)sk;
    e->pid = bpf_get_current_pid_tgid() >> 32;
    e->dir = 0;
    e->truncated = 0;

    /* skc_rcv_saddr/skc_daddr are stored network-order in the kernel;
     * convert to host order here so it matches what the TC program
     * computes from raw packet bytes via bpf_ntohl(). */
    e->saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    e->daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    e->len = 0;

    struct iov_iter iter = {};
    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) == 0) {
        if (iter.ubuf && iter.count) {
            u32 copy_len = (u32)iter.count;
            if (copy_len > sizeof(e->data)) {
                copy_len = sizeof(e->data);
                e->truncated = 1;
            }
            if (copy_len > 0) {
                e->len = copy_len;
                bpf_probe_read_user(e->data, copy_len, iter.ubuf);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}

SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(api_sentinel_recv_entry, struct sock *sk, struct msghdr *msg, size_t len, int flags)
{
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (__builtin_memcmp(comm, "uvicorn", 7) != 0)
        return 0;

    struct iov_iter iter = {};
    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) != 0)
        return 0;

    void *ubuf = iter.ubuf;
    if (!ubuf)
        return 0;

    struct recv_ctx rc = {};
    rc.ubuf = ubuf;
    rc.conn_id = (u64)sk;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&recv_bufs, &pid_tgid, &rc, BPF_ANY);
    return 0;
}

SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(api_sentinel_recv_exit, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct recv_ctx *rc = bpf_map_lookup_elem(&recv_bufs, &pid_tgid);
    if (!rc)
        return 0;

    void *ubuf = rc->ubuf;
    u64 conn_id = rc->conn_id;
    bpf_map_delete_elem(&recv_bufs, &pid_tgid);

    if (ret <= 0 || !ubuf)
        return 0;

    struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
    if (!e)
        return 0;

    e->ts = bpf_ktime_get_ns();
    e->conn_id = conn_id;
    e->pid = pid_tgid >> 32;
    e->dir = 1;
    e->truncated = 0;

    struct sock *sk = (struct sock *)conn_id;
    e->saddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr));
    e->daddr = bpf_ntohl(BPF_CORE_READ(sk, __sk_common.skc_daddr));
    e->sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    e->dport = bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));

    bpf_get_current_comm(e->comm, sizeof(e->comm));
    u32 copy_len = (u32)ret;
    if (copy_len > sizeof(e->data)) {
        copy_len = sizeof(e->data);
        e->truncated = 1;
    }

    e->len = copy_len;
    if (copy_len > 0)
        bpf_probe_read_user(e->data, copy_len, ubuf);

    bpf_ringbuf_submit(e, 0);
    return 0;
}

/* TC egress on lo: actual drop path (TC_ACT_SHOT), replaces the
 * earlier bpf_probe_write_user approach which always failed (-EFAULT)
 * since msg_iter is kernel memory, not user memory. */
SEC("tc")
int api_sentinel_egress(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end)
        return TC_ACT_OK;
    if (eth->h_proto != bpf_htons(ETH_P_IP))
        return TC_ACT_OK;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end)
        return TC_ACT_OK;
    if (ip->protocol != IPPROTO_TCP)
        return TC_ACT_OK;

    struct tcphdr *tcp = (void *)ip + (ip->ihl * 4);
    if ((void *)(tcp + 1) > data_end)
        return TC_ACT_OK;

    struct flow_key key;
    make_flow_key(&key,
        bpf_ntohl(ip->saddr), bpf_ntohl(ip->daddr),
        bpf_ntohs(tcp->source), bpf_ntohs(tcp->dest));

    u64 *expire = bpf_map_lookup_elem(&blocklist, &key);
    if (!expire)
        return TC_ACT_OK;
    if (*expire != 0 && bpf_ktime_get_ns() >= *expire)
        return TC_ACT_OK;

    return TC_ACT_SHOT;
}