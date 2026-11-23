#!/usr/bin/env bash
# Build the pinned kernel (sched_ext + BTF + lockdep), boot it in virtme-ng and run the
# upstream sched_ext selftests. Extra arguments go to the selftest runner (e.g. -t minimal).
#
#   KERNEL_SRC  kernel tree (default ~/linux); fetched at the pinned commit if missing
#   CPUS, MEM   guest size (default 4, 4G)
set -euo pipefail

repo=$(cd "$(dirname "$0")/../.." && pwd)
ksrc=${KERNEL_SRC:-$HOME/linux}
commit=${KERNEL_COMMIT:-$(cat "$repo/KERNEL_COMMIT")}

# v7.1 kfuncs with implicit args only get correct BTF when pahole emits bpf_kfunc decl tags (1.27+)
pahole_ver=$(pahole --version | tr -dc 0-9)
if [ "${pahole_ver:-0}" -lt 127 ]; then
	echo "error: pahole >= 1.27 required, found $(pahole --version)" >&2
	exit 1
fi

if [ ! -d "$ksrc/.git" ]; then
	git init -q "$ksrc"
	git -C "$ksrc" fetch --depth 1 https://github.com/torvalds/linux.git "$commit"
	git -C "$ksrc" checkout -q FETCH_HEAD
fi
head=$(git -C "$ksrc" rev-parse HEAD)
if [ "$head" != "$commit" ]; then
	echo "error: $ksrc is at $head, expected pinned $commit" >&2
	exit 1
fi

cd "$ksrc"
vng -v --build \
	--config tools/testing/selftests/sched_ext/config \
	--config "$repo/validation/vm/config"
make -C tools/testing/selftests/sched_ext -j"$(nproc)"

vng -v --user root --cpus "${CPUS:-4}" --memory "${MEM:-4G}" \
	-- ./tools/testing/selftests/sched_ext/runner "$@"
