/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I1 expect=runtime_error rule=I1.dsq_insert.commit_guards reason="dispatch buffer overflow"
 *
 * With dispatch_max_batch = 1, a second insert in one ops.dispatch would write past dspc->buf;
 * the cursor < dsp_max_batch guard aborts the scheduler instead.
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
	if (prev) {
		scx_bpf_dsq_insert(prev, DSQ, SCX_SLICE_DFL, 0);
		scx_bpf_dsq_insert(prev, DSQ, SCX_SLICE_DFL, 0);
	}
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.dispatch_max_batch = 1,
	.name		= "i1_dispatch_buffer_overflow",
};
