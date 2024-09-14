#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

SEC("uprobe")
int BPF_KPROBE(New, int a)
{
    bpf_printk("new ENTRY: size = %d", a);
    return 0;
}

SEC("uretprobe")
int BPF_KRETPROBE(retNew, char* ret)
{
    bpf_printk("new EXIT: return = %p", ret);
    return 0;
}