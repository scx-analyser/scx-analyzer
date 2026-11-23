#!/usr/bin/env python3
"""Build each validation test, run it in a fresh VM and classify what the kernel did.

  harness.py [TEST.bpf.c ...]         host side; default: every validation/tests/{pass,fail}/*.bpf.c
  harness.py guest OBJ LOADER SECS    inside the VM (started by the host side)

Each test declares `scxa: invariant=<id> expect=<outcome> [kfunc=<name>] [rule=<catalog rule id>]
[reason="<substring>"]` in a comment; with reason, the outcome's reason must also contain that substring.
Needs the kernel and the sched_ext selftests already built in $KERNEL_SRC (validation/vm/run-selftests.sh).
Env: KERNEL_SRC (default ~/linux), CPUS, MEM, SECS (seconds of load per test, default 5),
TIMEOUT (seconds per VM run including boot, default 120 + SECS).
"""
import json
import os
import re
import shlex
import signal
import subprocess
import sys
import time
from pathlib import Path

REPO = Path(__file__).resolve().parents[2]
TESTS = REPO / "validation" / "tests"
RESULTS = REPO / "validation" / "results"  # inside the repo: the guest cannot see the host's /tmp
OUTCOMES = ("verifier_reject", "runtime_error", "lockdep", "warn", "ok")  # what a test may expect
HARNESS_OUTCOMES = ("build_error", "harness_error", "timeout")  # the test could not be judged
FIELDS = ("invariant", "expect", "kfunc", "rule", "reason")
HEADER = re.compile(r"scxa:((?:\s+\w+=(?:\"[^\"]*\"|\S+))+)")
FIELD = re.compile(r"(\w+)=(?:\"([^\"]*)\"|(\S+))")
MARK = "SCXA_RESULT "
LOAD_LOG = "-- BEGIN PROG LOAD LOG --"

LOCKDEP = re.compile(
    r"^.*(WARNING: (possible |inconsistent lock|suspicious RCU|bad unlock|lock held|held lock|.*lock order)"
    r"|BUG: (sleeping function called|scheduling while atomic)).*$", re.M)
SCX_ERROR = re.compile(
    r'^.*sched_ext: BPF scheduler "([^"]+)" disabled \((runtime error|scx_bpf_error|runnable task stall)\).*$', re.M)
DISABLED = re.compile(r'^.*sched_ext: BPF scheduler "([^"]+)" disabled \(([^)]*)\).*$', re.M)
WARN = re.compile(r"^.*(WARNING: |BUG: |Oops).*$", re.M)


def parse_header(path):
    """Return {invariant, expect, kfunc, rule, reason} from the test's `scxa:` comment."""
    m = HEADER.search(Path(path).read_text())
    h = dict.fromkeys(FIELDS, "")
    found = {k: a or b for k, a, b in FIELD.findall(m.group(1))} if m else {}
    h |= found
    if h["expect"] not in OUTCOMES or not h["invariant"] or set(found) - set(FIELDS):
        raise ValueError(f"{path}: needs a `scxa: invariant=<id> expect=<{'|'.join(OUTCOMES)}> "
                         f"[kfunc=<name>] [rule=<id>] [reason=\"...\"]` comment")
    return h


def last_line(text):
    return (text.strip().splitlines() or [""])[-1]


def verifier_reason(out):
    log = out.split(LOAD_LOG)[-1].split("-- END PROG LOAD LOG --")[0]
    lines = [l.strip() for l in log.splitlines()
             if l.strip() and not l.startswith(("processed ", "verification time", "stack depth"))]
    return lines[-1] if lines else last_line(out)


def disabled_reason(dmesg, m):
    detail = re.search(rf"^.*sched_ext: {re.escape(m.group(1))}: (.*)$", dmesg, re.M)
    return f"{m.group(2)}: {detail.group(1).strip()}" if detail else m.group(2)


def classify(rc, out, dmesg, state="enabled"):
    """rc: loader exit code (0 = still attached at the end); state: /sys/kernel/sched_ext/state
    read at the end of the load. Returns (outcome, reason)."""
    if rc == 1:
        return "harness_error", f"loader exit 1: {last_line(out)}"
    if rc == 2:  # bpf_object__load() failed; only a kernel verifier log makes it a verifier reject
        if LOAD_LOG in out:
            return "verifier_reject", verifier_reason(out)
        return "harness_error", f"load failed without a verifier log: {last_line(out)}"
    if m := LOCKDEP.search(dmesg):
        return "lockdep", m.group(0).strip()
    if m := SCX_ERROR.search(dmesg):
        return "runtime_error", disabled_reason(dmesg, m)
    if m := WARN.search(dmesg):
        return "warn", m.group(0).strip()
    if rc != 0:
        return "runtime_error", f"loader exit {rc}: {last_line(out)}"
    if state != "enabled":  # e.g. scx_bpf_exit(): pr_info "disabled (unregistered from BPF)"
        m = DISABLED.search(dmesg)
        return "runtime_error", f"scheduler {state} under load" + (f": {disabled_reason(dmesg, m)}" if m else "")
    return "ok", ""


def debug_locks():
    """False if lockdep already turned itself off (it reports only once per boot)."""
    try:
        m = re.search(r"debug_locks:\s+(\d+)", Path("/proc/lockdep_stats").read_text())
    except OSError:
        return True
    return not m or m.group(1) != "0"


def guest(obj, loader, secs):
    def result(outcome, reason, rc=None, state=""):
        print(MARK + json.dumps({"outcome": outcome, "reason": reason, "loader_rc": rc, "scx_state": state}))

    if not debug_locks():
        print(f"--- dmesg ---\n{subprocess.run(['dmesg'], capture_output=True, text=True).stdout}")
        return result("harness_error", "lockdep was already disabled before the test (boot-time splat)")
    subprocess.run(["dmesg", "-C"], check=True)
    print("--- loader ---", flush=True)  # streamed, so a host-side timeout still keeps it
    p = subprocess.Popen([loader, obj], stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True)
    out, attached = [], False
    for line in p.stdout:  # until attached, or EOF if load/attach failed
        out.append(line)
        print(line, end="", flush=True)
        if line.startswith("SCXA_ATTACHED"):
            attached = True
            break
    if attached:
        # fork-heavy load drives select_cpu/enqueue/dispatch and task init/exit paths
        load = [subprocess.Popen(["sh", "-c", "while :; do /bin/true; done"]) for _ in range(os.cpu_count())]
        time.sleep(secs)
        state = Path("/sys/kernel/sched_ext/state").read_text().strip()
        for w in load:
            w.kill()
            w.wait()
    else:
        p.wait()
        state = Path("/sys/kernel/sched_ext/state").read_text().strip()
    rc = p.poll()
    if rc is None:
        p.terminate()
        rc = 0
    rest = p.communicate()[0]
    out.append(rest)
    print(rest, end="")
    time.sleep(1)  # let the disable work print
    dmesg = subprocess.run(["dmesg"], capture_output=True, text=True).stdout
    print(f"\n--- dmesg ---\n{dmesg}")
    result(*classify(rc, "".join(out), dmesg, state), rc, state)


def make_var(sel, var):
    rule = f"print-%:\n\t@echo $($*)\n"
    return subprocess.run(["make", "-s", "-C", sel, "-f", "Makefile", "-f", "-", f"print-{var}"],
                          input=rule, capture_output=True, text=True, check=True).stdout.strip()


def run_vm(cmd, cwd, timeout):
    """Run the VM; on timeout kill its whole process group (vng + qemu). Returns (log, timed_out)."""
    p = subprocess.Popen(cmd, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True,
                         start_new_session=True)
    try:
        return p.communicate(timeout=timeout)[0], False
    except subprocess.TimeoutExpired:
        os.killpg(p.pid, signal.SIGKILL)
        return p.communicate()[0], True


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
    secs = os.environ.get("SECS", "5")
    timeout = float(os.environ.get("TIMEOUT", 120 + float(secs)))
    vng = ["vng", "--user", "root", "--cpus", os.environ.get("CPUS", "4"),
           "--memory", os.environ.get("MEM", "4G"), "--"]

    outcomes = RESULTS / "outcomes.jsonl"
    outcomes.write_text("")
    failed = 0
    for test in tests:
        test = Path(test).resolve()
        name = test.name.removesuffix(".bpf.c")
        h = parse_header(test)
        obj = build / f"{name}.bpf.o"
        # every record has the same keys, so consumers can parse outcomes.jsonl blindly
        r = {"test": str(test.relative_to(REPO)) if test.is_relative_to(REPO) else str(test),
             **{k: h[k] for k in ("invariant", "kfunc", "rule", "expect")},
             "outcome": "", "reason": "", "loader_rc": None, "scx_state": ""}
        cc = subprocess.run([clang, *cflags, "-target", "bpf", "-c", str(test), "-o", str(obj)],
                            capture_output=True, text=True)
        if cc.returncode:
            r |= {"outcome": "build_error", "reason": last_line(cc.stderr)}
            log = cc.stderr
        else:
            log, timed_out = run_vm(vng + ["python3", __file__, "guest", str(obj), str(loader), secs],
                                    ksrc, timeout)
            line = next((l for l in log.splitlines() if l.startswith(MARK)), None)
            if line:
                r |= json.loads(line[len(MARK):])
            elif timed_out:
                r |= {"outcome": "timeout", "reason": f"no result after {timeout:.0f}s (hang or deadlock?)"}
            else:
                r |= {"outcome": "harness_error", "reason": f"VM exited without a result: {last_line(log)}"}
        (logs / f"{name}.log").write_text(log)
        r["pass"] = r["outcome"] == h["expect"] and h["reason"] in r["reason"]
        failed += not r["pass"]
        with open(outcomes, "a") as f:  # per test, so a later hang or crash keeps earlier results
            f.write(json.dumps(r) + "\n")
        want = h["expect"] + (f' "{h["reason"]}"' if h["reason"] else "")
        print(f"{'PASS' if r['pass'] else 'FAIL'}  {r['test']}  expect={want} got={r['outcome']}  {r['reason']}",
              flush=True)

    print(f"\n{len(tests) - failed}/{len(tests)} matched expectations; logs in {logs}")
    return 1 if failed else 0


if __name__ == "__main__":
    if sys.argv[1:2] == ["guest"]:
        guest(sys.argv[2], sys.argv[3], float(sys.argv[4]))
    else:
        sys.exit(host(sys.argv[1:] or sorted(TESTS.glob("*/*.bpf.c"))))
