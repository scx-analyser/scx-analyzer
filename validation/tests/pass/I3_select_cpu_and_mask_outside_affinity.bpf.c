/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=ok kfunc=scx_bpf_select_cpu_and rule=I3.idle.kfunc_allowed_mask
 *
 * For a pinned task (nr_cpus_allowed == 1) scx_bpf_select_cpu_and() only checks prev_cpu against the
 * caller's mask, not p->cpus_ptr. Called from ops.enqueue with another CPU as prev_cpu and the online
 * mask, it may claim (and clear the idle bit of) a CPU the task cannot run on. Nothing detects it:
 * expect ok, which documents the gap in the draft rule.
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
	if (p->nr_cpus_allowed == 1) {
		const struct cpumask *online = scx_bpf_get_online_cpumask();
		s32 other = (bpf_cpumask_first(p->cpus_ptr) + 1) % scx_bpf_nr_cpu_ids();

		scx_bpf_select_cpu_and(p, other, 0, online, 0);
		scx_bpf_put_cpumask(online);
	}
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
	.name		= "i3_select_cpu_and_mask_outside_affinity",
};
