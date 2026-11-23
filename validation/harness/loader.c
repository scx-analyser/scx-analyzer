// SPDX-License-Identifier: GPL-2.0
/*
 * Generic sched_ext loader: lets a test be a single .bpf.c with no user-space skeleton.
 *
 *   loader OBJ    open OBJ, fill its __SCX_* enum constants from vmlinux BTF (what
 *                 SCX_ENUM_INIT() does for skeletons), load it, attach every struct_ops
 *                 map, print "SCXA_ATTACHED", then stay attached until killed.
 *
 * Exit codes: 1 open/setup error, 2 load (verifier) failure, 3 attach failure.
 */
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <bpf/btf.h>
#include <bpf/libbpf.h>

static int vmlinux_enum(const struct btf *btf, const char *name, __u64 *val)
{
	__u32 id, n = btf__type_cnt(btf);

	for (id = 1; id < n; id++) {
		const struct btf_type *t = btf__type_by_id(btf, id);
		__u16 i, vlen = btf_vlen(t);

		if (btf_is_enum(t)) {
			const struct btf_enum *e = btf_enum(t);

			for (i = 0; i < vlen; i++, e++)
				if (!strcmp(btf__name_by_offset(btf, e->name_off), name)) {
					*val = btf_kflag(t) ? (__u64)(__s64)e->val : (__u32)e->val;
					return 0;
				}
		} else if (btf_is_enum64(t)) {
			const struct btf_enum64 *e = btf_enum64(t);

			for (i = 0; i < vlen; i++, e++)
				if (!strcmp(btf__name_by_offset(btf, e->name_off), name)) {
					*val = btf_enum64_value(e);
					return 0;
				}
		}
	}
	return -ENOENT;
}

/* scx headers declare enum values as `const volatile u64 __SCX_FOO` in .rodata. */
static int fill_scx_enums(struct bpf_object *obj)
{
	struct bpf_map *rodata = bpf_object__find_map_by_name(obj, ".rodata");
	struct btf *btf = bpf_object__btf(obj), *vmlinux;
	const struct btf_var_secinfo *vs;
	const struct btf_type *sec;
	char *data;
	size_t size;
	int id, i;

	if (!rodata || !btf)
		return 0;
	id = btf__find_by_name_kind(btf, ".rodata", BTF_KIND_DATASEC);
	if (id < 0)
		return 0;
	vmlinux = btf__load_vmlinux_btf();
	if (!vmlinux) {
		fprintf(stderr, "loader: cannot load vmlinux BTF\n");
		return -1;
	}
	sec = btf__type_by_id(btf, id);
	data = bpf_map__initial_value(rodata, &size);
	vs = btf_var_secinfos(sec);
	for (i = 0; i < btf_vlen(sec); i++, vs++) {
		const char *name = btf__name_by_offset(btf, btf__type_by_id(btf, vs->type)->name_off);
		__u64 val;

		if (strncmp(name, "__SCX_", 6) || vs->size != sizeof(val) ||
		    vmlinux_enum(vmlinux, name + 2, &val))
			continue; /* unknown on this kernel: stays 0, like SCX_ENUM_INIT */
		memcpy(data + vs->offset, &val, sizeof(val));
	}
	btf__free(vmlinux);
	return 0;
}

int main(int argc, char **argv)
{
	struct bpf_object *obj;
	struct bpf_map *map;

	if (argc != 2) {
		fprintf(stderr, "usage: %s OBJ.bpf.o\n", argv[0]);
		return 1;
	}
	obj = bpf_object__open_file(argv[1], NULL);
	if (!obj) {
		fprintf(stderr, "loader: cannot open %s: %s\n", argv[1], strerror(errno));
		return 1;
	}
	if (fill_scx_enums(obj))
		return 1;
	if (bpf_object__load(obj)) {
		fprintf(stderr, "loader: load failed: %s\n", strerror(errno));
		return 2;
	}
	bpf_object__for_each_map(map, obj) {
		if (bpf_map__type(map) != BPF_MAP_TYPE_STRUCT_OPS)
			continue;
		if (!bpf_map__attach_struct_ops(map)) {
			fprintf(stderr, "loader: attach %s failed: %s\n",
				bpf_map__name(map), strerror(errno));
			return 3;
		}
	}
	printf("SCXA_ATTACHED\n");
	fflush(stdout);
	pause(); /* SIGTERM closes the link fds, which unregisters the scheduler */
	return 0;
}
