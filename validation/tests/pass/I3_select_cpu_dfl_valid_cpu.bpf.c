/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=ok kfunc=scx_bpf_select_cpu_dfl rule=I3.idle.cpu_arg
 *
 * scx_bpf_select_cpu_dfl() validates prev_cpu before using it; the kernel-supplied prev_cpu passes.
 */
#include <scx/common.bpf.h>

char _license[] SEC("license") = "GPL";

#define DSQ 0

s32 BPF_STRUCT_OPS_SLEEPABLE(t_init)
{
	return scx_bpf_create_dsq(DSQ, -1);
}

s32 BPF_STRUCT_OPS(t_select_cpu, struct task_struct *p, s32 prev_cpu, u64 wake_flags)
{
	bool is_idle;

	return scx_bpf_select_cpu_dfl(p, prev_cpu, wake_flags, &is_idle);
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
	.select_cpu	= (void *)t_select_cpu,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i3_select_cpu_dfl_valid_cpu",
};
