#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

#define MAX_CAPTURE_LEN 4096

struct event {
    u64 ts;
    u64 conn_id;
    u32 pid;
    u32 len;       
    u8 dir;
    u8 truncated; 
    char comm[16];
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

SEC("kprobe/tcp_sendmsg_locked")
int BPF_KPROBE(api_sentinel,
               struct sock *sk,
               struct msghdr *msg,
               size_t size)
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

/* Entry: stash the destination buffer pointer for this call so the
 * kretprobe can read it after the kernel has copied data in. */
SEC("kprobe/tcp_recvmsg")
int BPF_KPROBE(api_sentinel_recv_entry,
               struct sock *sk,
               struct msghdr *msg,
               size_t len,
               int flags)
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

/* Return: ret is the number of bytes actually copied into the buffer
 * we stashed on entry (or a negative errno). */
SEC("kretprobe/tcp_recvmsg")
int BPF_KRETPROBE(api_sentinel_recv_exit, int ret)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    struct recv_ctx *rc = bpf_map_lookup_elem(&recv_bufs, &pid_tgid);
    if (!rc) {
        return 0;
    }

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
    e->dir = 1; /* request */
    e->truncated = 0;

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