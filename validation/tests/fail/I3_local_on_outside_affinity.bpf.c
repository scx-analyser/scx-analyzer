/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=runtime_error kfunc=scx_bpf_dsq_insert rule=I3.affinity.remote_local_dsq reason="not allowed for"
 *
 * Pinned tasks (per-CPU kthreads, nr_cpus_allowed == 1) are sent to another CPU's local DSQ.
 * task_can_run_on_remote_rq(enforce=true) rejects that with scx_error, not a fallback.
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
		s32 cpu = bpf_cpumask_first(p->cpus_ptr);

		scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | ((cpu + 1) % scx_bpf_nr_cpu_ids()),
				   SCX_SLICE_DFL, enq_flags);
		return;
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
	.name		= "i3_local_on_outside_affinity",
};
