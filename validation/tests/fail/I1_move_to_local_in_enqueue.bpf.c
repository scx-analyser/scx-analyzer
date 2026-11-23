/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=verifier_reject kfunc=scx_bpf_dsq_move_to_local rule=I1.dispatch_only.context reason="scx_bpf_dsq_move_to_local is not allowed"
 *
 * scx_bpf_dsq_move_to_local() is dispatch-only; scx_kfunc_context_filter() rejects the
 * call from ops.enqueue at load time.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define DSQ 0

s32 BPF_STRUCT_OPS_SLEEPABLE(t_init)
{
	return scx_bpf_create_dsq(DSQ, -1);
}

void BPF_STRUCT_OPS(t_enqueue, struct task_struct *p, u64 enq_flags)
{
	scx_bpf_dsq_insert(p, DSQ, SCX_SLICE_DFL, enq_flags);
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.name		= "i1_move_to_local_in_enqueue",
};
