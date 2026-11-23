/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=runtime_error kfunc=scx_bpf_dsq_move rule=I3.dsq_id.dispatch_target reason="non-existent DSQ 0xcafef00d"
 *
 * scx_bpf_dsq_move() resolves its destination with find_dsq_for_dispatch(): a non-existent DSQ is
 * scx_error and the task lands on the global DSQ. Pass variant: pass/I1_dsq_move_in_dispatch.
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
	struct task_struct *p;

	bpf_for_each(scx_dsq, p, DSQ, 0)
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, 0xcafef00d, 0))
			return;
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i3_dsq_move_bogus_dsq",
};
