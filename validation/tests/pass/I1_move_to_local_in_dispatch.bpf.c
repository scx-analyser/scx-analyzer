/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=ok kfunc=scx_bpf_dsq_move_to_local rule=I1.dispatch_only.context
 *
 * scx_bpf_dsq_move_to_local() is in the dispatch kfunc set; ops.dispatch may call it.
 * It only moves from user-created DSQs (built-in ones such as SCX_DSQ_GLOBAL are a runtime error).
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
}

void BPF_STRUCT_OPS(t_dispatch, s32 cpu, struct task_struct *prev)
{
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i1_move_to_local_in_dispatch",
};
