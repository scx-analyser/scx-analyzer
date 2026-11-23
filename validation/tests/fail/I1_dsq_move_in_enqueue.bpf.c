/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=verifier_reject
 *
 * ops.enqueue runs with the task's rq locked; scx_bpf_dsq_move() would take a DSQ and rq lock
 * under it, so the kfunc context filter rejects it there (dispatch and unlocked ops only).
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
	struct task_struct *q;

	scx_bpf_dsq_insert(p, DSQ, SCX_SLICE_DFL, enq_flags);
	bpf_for_each(scx_dsq, q, DSQ, 0)
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, q, SCX_DSQ_GLOBAL, 0))
			break;
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
	.name		= "i1_dsq_move_in_enqueue",
};
