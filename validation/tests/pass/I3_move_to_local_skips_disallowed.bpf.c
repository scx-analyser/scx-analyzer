/* SPDX-License-Identifier: GPL-2.0 */
/*
 * scxa: invariant=I3 expect=ok kfunc=scx_bpf_dsq_move_to_local rule=I3.affinity.remote_local_dsq
 *
 * Pinned per-CPU kthreads share one user DSQ with everything else, so CPUs outside their affinity
 * keep consuming it. consume_dispatch_q() calls task_can_run_on_remote_rq(enforce=false) and skips
 * them silently: expect ok, which documents that this path has no detection, only avoidance.
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
	scx_bpf_dsq_move_to_local(DSQ, 0);
}

SEC(".struct_ops.link")
struct sched_ext_ops t_ops = {
	.init		= (void *)t_init,
	.enqueue	= (void *)t_enqueue,
	.dispatch	= (void *)t_dispatch,
	.name		= "i3_move_to_local_skips_disallowed",
};
