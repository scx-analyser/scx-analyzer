#!/usr/bin/env bash
# Build LLVM IR (with DWARF debug info) for the sched_ext parts of the pinned kernel.
#
#   extractor/build_kernel_ir.sh [--kernel-src DIR] [--build-dir DIR] [-j N]
#                                [--allow-kernel-mismatch]
#
# Output (in --build-dir, default extractor/build/):
#   kernel/sched/build_policy.ll   ext.c, ext_idle.c (and the other policy files)
#   kernel/sched/core.ll
#   .config                        the exact configuration used
#   ir-manifest.txt                kernel commit, toolchain, config hash, IR hashes
#
# Only `make prepare` and the two .ll targets are built, not a full kernel.
# The kernel tree defaults to $KERNEL_SRC, then ~/linux. If it does not exist,
# it is fetched at the pinned commit. The tree's HEAD must be the pinned commit
# (KERNEL_COMMIT, else the v7.1 default below); --allow-kernel-mismatch turns
# that into a warning for exploratory runs.
set -euo pipefail

repo=$(cd "$(dirname "$0")/.." && pwd)
ksrc=${KERNEL_SRC:-$HOME/linux}
build=$repo/extractor/build
jobs=$(nproc)
allow_mismatch=0

while [ $# -gt 0 ]; do
	case $1 in
	--kernel-src) ksrc=$2; shift 2 ;;
	--build-dir) build=$2; shift 2 ;;
	-j) jobs=$2; shift 2 ;;
	--allow-kernel-mismatch) allow_mismatch=1; shift ;;
	-h|--help) sed -n '2,17p' "$0"; exit 0 ;;
	*) echo "error: unknown argument $1" >&2; exit 2 ;;
	esac
done

# Pin: KERNEL_COMMIT (added with the A1 inventory) wins; until then the v7.1 commit
# that catalog/, checker/ and validation/ already reference.
pin_tag=v7.1
pin_commit=8cd9520d35a6c38db6567e97dd93b1f11f185dc6
if [ -f "$repo/KERNEL_COMMIT" ]; then
	pin_commit=$(grep -v '^#' "$repo/KERNEL_COMMIT" | head -n1 | tr -d '[:space:]')
fi
if grep -qv '^\(#\|TBD\)' "$repo/KERNEL_VERSION" 2>/dev/null; then
	pin_tag=$(grep -v '^#' "$repo/KERNEL_VERSION" | head -n1 | tr -d '[:space:]')
fi

for tool in clang ld.lld llvm-ar make flex bison bc; do
	command -v "$tool" >/dev/null || { echo "error: $tool not found (see extractor/README.md)" >&2; exit 1; }
done

if [ ! -e "$ksrc" ]; then
	echo "fetching $pin_tag ($pin_commit) into $ksrc"
	git init -q "$ksrc"
	git -C "$ksrc" fetch -q --depth 1 https://github.com/torvalds/linux.git "$pin_commit"
	git -C "$ksrc" checkout -q FETCH_HEAD
fi
ksrc=$(cd "$ksrc" && pwd)

head=$(git -C "$ksrc" rev-parse --verify HEAD 2>/dev/null || echo "not-a-git-tree")
if [ "$head" != "$pin_commit" ]; then
	msg="$ksrc is at $head, expected pinned $pin_tag ($pin_commit)"
	if [ "$allow_mismatch" = 1 ]; then
		echo "warning: $msg" >&2
	else
		echo "error: $msg; check it out or pass --allow-kernel-mismatch" >&2
		exit 1
	fi
fi
if [ -n "$(git -C "$ksrc" status --porcelain --untracked-files=no -- kernel/sched include 2>/dev/null)" ]; then
	echo "error: $ksrc has local changes under kernel/sched or include" >&2
	exit 1
fi

mkdir -p "$build"
build=$(cd "$build" && pwd)
kmake() { make -C "$ksrc" O="$build" LLVM=1 -j"$jobs" "$@"; }

kmake defconfig >/dev/null
"$ksrc/scripts/kconfig/merge_config.sh" -m -O "$build" "$build/.config" \
	"$ksrc/tools/testing/selftests/sched_ext/config" "$repo/extractor/kernel.config" >/dev/null
kmake olddefconfig >/dev/null

# Fail loudly if Kconfig dropped an option the analysis depends on.
for opt in SCHED_CLASS_EXT DEBUG_INFO DEBUG_INFO_BTF PROVE_LOCKING EXT_GROUP_SCHED SCHED_CORE; do
	grep -q "^CONFIG_$opt=y" "$build/.config" || { echo "error: CONFIG_$opt is not enabled after olddefconfig" >&2; exit 1; }
done

kmake prepare >/dev/null
kmake kernel/sched/build_policy.ll kernel/sched/core.ll

manifest=$build/ir-manifest.txt
{
	echo "kernel_tag: $pin_tag"
	echo "kernel_commit: $head"
	echo "clang: $(clang --version | head -n1)"
	echo "config_sha256: $(sha256sum "$build/.config" | cut -d' ' -f1)"
	for ll in kernel/sched/build_policy.ll kernel/sched/core.ll; do
		echo "ir: $ll $(sha256sum "$build/$ll" | cut -d' ' -f1)"
	done
} >"$manifest"
cat "$manifest"
