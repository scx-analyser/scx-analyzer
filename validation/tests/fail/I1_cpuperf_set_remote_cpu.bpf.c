/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=runtime_error rule=I1.rq_scx.rq_lock reason="Invalid target CPU"
 *
 * With one rq lock held, writing another CPU's cpuperf_target would need a second rq lock
 * (ABBA risk), so scx_bpf_cpuperf_set() rejects it at runtime: "Invalid target CPU". Needs CPUS > 1.
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
	scx_bpf_cpuperf_set((cpu + 1) % scx_bpf_nr_cpu_ids(), SCX_CPUPERF_ONE);
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i1_cpuperf_set_remote_cpu",
};
