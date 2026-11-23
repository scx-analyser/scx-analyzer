/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=ok rule=I1.dsq_move.context
 *
 * scx_bpf_dsq_move() takes the source DSQ lock itself, so it is only allowed where no rq/DSQ
 * lock it could invert against is held by the caller: ops.dispatch or unlocked ops.
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

	/* moving a task the kernel can't migrate here is a runtime error, not a fallback */
	bpf_for_each(scx_dsq, p, DSQ, 0)
		if (!is_migration_disabled(p) && bpf_cpumask_test_cpu(cpu, p->cpus_ptr) &&
		    scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
			return;
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i1_dsq_move_in_dispatch",
};
