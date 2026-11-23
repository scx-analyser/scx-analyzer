/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=ok kfunc=scx_bpf_dsq_insert rule=I3.affinity.remote_local_dsq
 *
 * Every task goes to the local DSQ of another CPU in its cpus_ptr when it has one, so the
 * remote-rq affinity check (task_can_run_on_remote_rq) runs and passes.
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
	u32 nr = scx_bpf_nr_cpu_ids(), i;
	s32 cpu = scx_bpf_task_cpu(p), target = -1;

	bpf_for(i, 1, nr) {
		s32 c = (cpu + i) % nr;

		if (bpf_cpumask_test_cpu(c, p->cpus_ptr)) {
			target = c;
			break;
		}
	}
	if (target < 0)
		target = bpf_cpumask_test_cpu(cpu, p->cpus_ptr) ? cpu : bpf_cpumask_first(p->cpus_ptr);
	scx_bpf_dsq_insert(p, SCX_DSQ_LOCAL_ON | target, SCX_SLICE_DFL, enq_flags);
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
	.name		= "i3_local_on_allowed_cpu",
};
