/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=runtime_error kfunc=scx_bpf_test_and_clear_cpu_idle rule=I3.idle.cpu_arg reason="invalid CPU 1023"
 *
 * scx_bpf_test_and_clear_cpu_idle() checks its CPU argument (0 <= cpu < nr_cpu_ids, possible) before touching per-CPU
 * state; CPU 1023 does not exist, so it is a runtime error.
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
	scx_bpf_test_and_clear_cpu_idle(1023);
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
	.name		= "i3_test_and_clear_cpu_idle_invalid_cpu",
};
