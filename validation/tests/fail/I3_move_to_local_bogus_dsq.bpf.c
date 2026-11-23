/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=runtime_error kfunc=scx_bpf_dsq_move_to_local rule=I3.dsq_id.dispatch_target reason="invalid DSQ ID 0x00000000cafef00d"
 *
 * The source of scx_bpf_dsq_move_to_local() must be an existing user DSQ; anything else is
 * scx_error + return false. Pass variant: pass/I3_insert_created_dsq.
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
	if (!scx_bpf_dsq_move_to_local(0xcafef00d, 0))
		scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i3_move_to_local_bogus_dsq",
};
