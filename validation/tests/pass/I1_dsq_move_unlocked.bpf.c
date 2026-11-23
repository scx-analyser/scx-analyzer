/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=ok kfunc=scx_bpf_dsq_move rule=I1.dsq_move.slice_vtime
 *
 * ops.init_task holds no rq lock (fork path and enable loop both drop it), so scx_bpf_dsq_move()
 * takes the !in_balance branch: it locks task_rq(p) itself before the slice/vtime writes.
 * Moving to SCX_DSQ_GLOBAL avoids the local-DSQ affinity checks.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define DSQ 0

s32 BPF_STRUCT_OPS_SLEEPABLE(t_init)
{
	return scx_bpf_create_dsq(DSQ, -1);
}

s32 BPF_STRUCT_OPS(t_init_task, struct task_struct *p, struct scx_init_task_args *args)
{
	struct task_struct *q;

	bpf_for_each(scx_dsq, q, DSQ, 0) {
		scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, SCX_SLICE_DFL / 2);
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, q, SCX_DSQ_GLOBAL, 0))
			break;
	}
	return 0;
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
	.init_task	= (void *)t_init_task,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i1_dsq_move_unlocked",
};
