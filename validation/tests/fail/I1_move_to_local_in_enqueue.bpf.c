/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=verifier_reject
 *
 * scx_bpf_dsq_move_to_local() is dispatch-only; scx_kfunc_context_filter() rejects the
 * call from ops.enqueue at load time.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

void BPF_STRUCT_OPS(t_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, SCX_DSQ_GLOBAL, SCX_SLICE_DFL, enq_flags);
	scx_bpf_dsq_move_to_local(SCX_DSQ_GLOBAL, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.enqueue	= (void *)t_enqueue,
	.name		= "i1_move_to_local_in_enqueue",
};
