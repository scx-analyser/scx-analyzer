/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=ok kfunc=scx_bpf_dsq_insert_vtime rule=I3.dsq_id.vtime_ordering
 *
 * vtime ordering on a user DSQ that only ever gets vtime inserts.
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
	scx_bpf_dsq_insert_vtime(p, DSQ, SCX_SLICE_DFL, p->scx.dsq_vtime, enq_flags);
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
	.name		= "i3_insert_vtime_user_dsq",
};
