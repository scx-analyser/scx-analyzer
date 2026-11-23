/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=runtime_error kfunc=scx_bpf_dsq_insert reason="non-existent DSQ 0xcafef00d"
 *
 * Inserting into a DSQ id that was never created passes the verifier (the id is just a u64)
 * but the kernel's DSQ lookup fails at runtime and scx_error() ejects the scheduler.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

void BPF_STRUCT_OPS(t_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, 0xcafef00d, SCX_SLICE_DFL, enq_flags);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.enqueue	= (void *)t_enqueue,
	.name		= "i3_insert_bogus_dsq",
};
