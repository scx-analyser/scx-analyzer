#!/usr/bin/env python3
"""Build each validation test, run it in a fresh VM and classify what the kernel did.

  harness.py [TEST.bpf.c ...]         host side; default: every validation/tests/{pass,fail}/*.bpf.c
  harness.py guest OBJ LOADER SECS    inside the VM (started by the host side)

Each test declares `scxa: invariant=<id> expect=<outcome>` in a comment. Needs the kernel and the
sched_ext selftests already built in $KERNEL_SRC (validation/vm/run-selftests.sh does that).
Env: KERNEL_SRC (default ~/linux), CPUS, MEM, SECS (seconds of load per test, default 5).
"""
import json
import os
import re
import shlex
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / "validation" / "tests"
RESULTS = REPO / "validation" / "results"  # inside the repo: the guest cannot see the host's /tmp
OUTCOMES = ("verifier_reject", "runtime_error", "lockdep", "warn", "ok")
HEADER = re.compile(r"scxa:\s*invariant=(\S+)\s+expect=(\S+)")
MARK = "SCXA_RESULT "

LOCKDEP = re.compile(
    r"^.*(WARNING: (possible |inconsistent lock|suspicious RCU|bad unlock|lock held|held lock|.*lock order)"
    r"|BUG: (sleeping function called|scheduling while atomic)).*$", re.M)
SCX_ERROR = re.compile(
    r'^.*sched_ext: BPF scheduler "([^"]+)" disabled \((runtime error|scx_bpf_error|runnable task stall)\).*$', re.M)
WARN = re.compile(r"^.*(WARNING: |BUG: |Oops).*$", re.M)


def parse_header(path):
    m = HEADER.search(Path(path).read_text())
    if not m or m.group(2) not in OUTCOMES:
        raise ValueError(f"{path}: needs a `scxa: invariant=<id> expect=<{'|'.join(OUTCOMES)}>` comment")
    return m.group(1), m.group(2)


def verifier_reason(out):
    log = out.split("-- BEGIN PROG LOAD LOG --")[-1].split("-- END PROG LOAD LOG --")[0]
    lines = [l.strip() for l in log.splitlines()
             if l.strip() and not l.startswith(("processed ", "verification time", "stack depth"))]
    return lines[-1] if lines else (out.strip().splitlines() or [""])[-1]


def classify(rc, out, dmesg):
    """rc: loader exit code (0 = still attached at the end). Returns (outcome, reason)."""
    if rc == 2:
        return "verifier_reject", verifier_reason(out)
    if m := LOCKDEP.search(dmesg):
        return "lockdep", m.group(0).strip()
    if m := SCX_ERROR.search(dmesg):
        detail = re.search(rf"^.*sched_ext: {re.escape(m.group(1))}: (.*)$", dmesg, re.M)
        return "runtime_error", f"{m.group(2)}: {detail.group(1).strip()}" if detail else m.group(2)
    if m := WARN.search(dmesg):
        return "warn", m.group(0).strip()
    if rc != 0:
        tail = out.strip().splitlines()[-1:] or [""]
        return "runtime_error", f"loader exit {rc}: {tail[0]}"
    return "ok", ""


def guest(obj, loader, secs):
    subprocess.run(["dmesg", "-C"], check=True)
    p = subprocess.Popen([loader, obj], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out = []
    for line in p.stdout:  # until attached, or EOF if load/attach failed
        out.append(line)
        if line.startswith("SCXA_ATTACHED"):
            break
    # fork-heavy load drives select_cpu/enqueue/dispatch and task init/exit paths
    load = [subprocess.Popen(["sh", "-c", "while :; do /bin/true; done"]) for _ in range(os.cpu_count())]
    time.sleep(secs)
    state = Path("/sys/kernel/sched_ext/state").read_text().strip()
    for w in load:
        w.kill()
    rc = p.poll() or 0
    if p.returncode is None:
        p.terminate()
    out.append(p.communicate()[0])
    out = "".join(out)
    time.sleep(1)  # let the disable work print
    dmesg = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    outcome, reason = classify(rc, out, dmesg)
    print(f"--- loader ---\n{out}\n--- dmesg ---\n{dmesg}")
    print(MARK + json.dumps({"outcome": outcome, "reason": reason, "loader_rc": rc, "scx_state": state}))


def make_var(sel, var):
    rule = f"print-%:\n\t@echo $($*)\n"
    return subprocess.run(["make", "-s", "-C", sel, "-f", "Makefile", "-f", "-", f"print-{var}"],
                          input=rule, capture_output=True, text=True, check=True).stdout.strip()


def host(tests):
    ksrc = Path(os.environ.get("KERNEL_SRC", Path.home() / "linux"))
    sel = ksrc / "tools/testing/selftests/sched_ext"
    build, logs = RESULTS / "build", RESULTS / "logs"
    build.mkdir(parents=True, exist_ok=True)
    logs.mkdir(parents=True, exist_ok=True)
    loader = build / "loader"
    subprocess.run(["cc", "-O2", "-g", f"-I{sel}/build/include", f"-I{ksrc}/tools/include/uapi",
                    str(Path(__file__).parent / "loader.c"), f"{sel}/build/obj/libbpf/libbpf.a",
                    "-lelf", "-lz", "-lzstd", "-o", str(loader)], check=True)
    clang = make_var(sel, "CLANG") or "clang"
    cflags = shlex.split(make_var(sel, "BPF_CFLAGS"))
    vng = ["vng", "--user", "root", "--cpus", os.environ.get("CPUS", "4"),
           "--memory", os.environ.get("MEM", "4G"), "--"]

    results = []
    for test in tests:
        test = Path(test).resolve()
        name = test.name.removesuffix(".bpf.c")
        invariant, expect = parse_header(test)
        obj = build / f"{name}.bpf.o"
        r = {"test": str(test.relative_to(REPO)), "invariant": invariant, "expect": expect}
        cc = subprocess.run([clang, *cflags, "-target", "bpf", "-c", str(test), "-o", str(obj)],
                            capture_output=True, text=True)
        if cc.returncode:
            r |= {"outcome": "build_error", "reason": (cc.stderr.strip().splitlines() or [""])[-1]}
            log = cc.stderr
        else:
            run = subprocess.run(vng + ["python3", __file__, "guest", str(obj), str(loader),
                                        os.environ.get("SECS", "5")],
                                 cwd=ksrc, capture_output=True, text=True)
            log = run.stdout + run.stderr
            line = next((l for l in log.splitlines() if l.startswith(MARK)), None)
            r |= json.loads(line[len(MARK):]) if line else {"outcome": "harness_error",
                                                            "reason": f"vng exit {run.returncode}"}
        (logs / f"{name}.log").write_text(log)
        r["pass"] = r["outcome"] == expect
        results.append(r)
        print(f"{'PASS' if r['pass'] else 'FAIL'}  {r['test']}  expect={expect} got={r['outcome']}  {r['reason']}",
              flush=True)

    with open(RESULTS / "outcomes.jsonl", "w") as f:
        f.writelines(json.dumps(r) + "\n" for r in results)
    failed = sum(not r["pass"] for r in results)
    print(f"\n{len(results) - failed}/{len(results)} matched expectations; logs in {logs}")
    return 1 if failed else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["guest"]:
        guest(sys.argv[2], sys.argv[3], float(sys.argv[4]))
    else:
        sys.exit(host(sys.argv[1:] or sorted(TESTS.glob("*/*.bpf.c"))))
