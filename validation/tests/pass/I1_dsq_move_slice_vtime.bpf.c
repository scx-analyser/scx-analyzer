/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=ok kfunc=scx_bpf_dsq_move rule=I1.dsq_move.slice_vtime
 *
 * Setting slice and vtime on the iterator makes scx_bpf_dsq_move() write p->scx.slice and
 * p->scx.dsq_vtime, which it does under task_rq(p) and the source DSQ lock (in_balance branch).
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

	bpf_for_each(scx_dsq, p, DSQ, 0) {
		if (is_migration_disabled(p) || !bpf_cpumask_test_cpu(cpu, p->cpus_ptr))
			continue;
		scx_bpf_dsq_move_set_slice(BPF_FOR_EACH_ITER, SCX_SLICE_DFL / 2);
		scx_bpf_dsq_move_set_vtime(BPF_FOR_EACH_ITER, p->scx.dsq_vtime + 1);
		if (scx_bpf_dsq_move(BPF_FOR_EACH_ITER, p, SCX_DSQ_LOCAL, 0))
			return;
	}
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i1_dsq_move_slice_vtime",
};
