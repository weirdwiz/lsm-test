//+build ignore

#ifdef asm_inline
#undef asm_inline
#define asm_inline asm
#endif

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

typedef __u64 u64;
char LICENSE[] SEC("license") = "Dual BSD/GPL";

int monitored_pid = 0;
int mprotect_count = 0;
int bprm_count = 0;

#define EPERM  1

struct {
    __uint(type, BPF_MAP_TYPE_PERF_EVENT_ARRAY);
    __uint(key_size, sizeof(u32));
    __uint(value_size, sizeof(u32));
} events SEC(".maps");

SEC("kprobe/sys_mmap")
int kprobe__sys_mmap(struct pt_regs *ctx)
{
    int process = 2021;
    bpf_perf_event_output(ctx, &events, BPF_F_CURRENT_CPU, &process, sizeof(int));

    return 0;
}

SEC("lsm/file_mprotect")
int BPF_PROG(test_int_hook, struct vm_area_struct *vma,
	     unsigned long reqprot, unsigned long prot, int ret)
{
    bpf_trace_printk("printing stuff", 4096);
	if (ret != 0)
		return ret;

	__u32 pid = bpf_get_current_pid_tgid() >> 32;
	int is_stack = 0;

	is_stack = (vma->vm_start <= vma->vm_mm->start_stack &&
		    vma->vm_end >= vma->vm_mm->start_stack);

	if (is_stack && monitored_pid == pid) {
		mprotect_count++;
		ret = -EPERM;
	}

	return ret;
}
