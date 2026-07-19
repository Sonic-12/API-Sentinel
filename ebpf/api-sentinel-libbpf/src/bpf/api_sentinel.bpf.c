#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "GPL";

struct event {
    u64 ts;
    u32 pid;
    u32 len;
    char comm[16];
    char data[256];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1 << 24);
} events SEC(".maps");

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
    e->pid = bpf_get_current_pid_tgid() >> 32;

    __builtin_memcpy(e->comm, comm, sizeof(e->comm));
    __builtin_memset(e->data, 0, sizeof(e->data));
    e->len = 0;

    struct iov_iter iter = {};

    if (bpf_probe_read_kernel(&iter, sizeof(iter), &msg->msg_iter) == 0) {

        if (iter.ubuf && iter.count) {

            /* Verifier-friendly bounded length */
            u32 copy_len = (u32)iter.count;
            copy_len &= 0xff;

            if (copy_len > sizeof(e->data))
                copy_len = sizeof(e->data);

            if (copy_len > 0) {
                e->len = copy_len;
                bpf_probe_read_user(e->data, copy_len, iter.ubuf);
            }
        }
    }

    bpf_ringbuf_submit(e, 0);
    return 0;
}