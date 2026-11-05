#!/usr/bin/env python3
"""Create labels, milestones, epics and task sub-issues from planning/issues.yaml.

Uses only the GitHub REST API through the `gh` CLI (no GraphQL).

    gh auth login                       # once
    python3 planning/create_issues.py --repo scx-analyser/scx-analyzer --dry-run
    python3 planning/create_issues.py --repo scx-analyser/scx-analyzer \
        --assign A=alice --assign B=bob --assign C=carol --assign D=dave

Idempotent: issues are matched by exact title, so re-running only creates
what is missing (and re-links sub-issues / refreshes epic checklists).
"""
import argparse
import json
import subprocess
import sys
from pathlib import Path

import yaml

HERE = Path(__file__).resolve().parent


class GH:
    def __init__(self, repo: str, dry: bool):
        self.repo, self.dry = repo, dry
        self._fake = 1000

    def api(self, method, path, fields=None, paginate=False, allow_fail=False):
        url = f"repos/{self.repo}/{path}" if path else f"repos/{self.repo}"
        if self.dry and method != "GET":
            print(f"[dry-run] {method} {url} {json.dumps(fields or {})[:160]}")
            self._fake += 1
            return {"number": self._fake, "id": self._fake, "html_url": f"#{self._fake}"}
        cmd = ["gh", "api", "-X", method, url, "-H", "Accept: application/vnd.github+json"]
        if paginate:
            cmd += ["--paginate", "--slurp"]
        inp = None
        if fields is not None:
            cmd += ["--input", "-"]
            inp = json.dumps(fields)
        r = subprocess.run(cmd, input=inp, capture_output=True, text=True)
        if r.returncode != 0:
            if allow_fail:
                return None
            sys.exit(f"gh api {method} {url} failed:\n{r.stderr or r.stdout}")
        out = json.loads(r.stdout) if r.stdout.strip() else {}
        if paginate:  # --slurp wraps pages in a list
            out = [x for page in out for x in page]
        return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--repo", required=True)
    ap.add_argument("--plan", default=str(HERE / "issues.yaml"))
    ap.add_argument("--assign", action="append", default=[], help="EPIC=github-login, e.g. A=alice")
    ap.add_argument("--dry-run", action="store_true")
    a = ap.parse_args()

    plan = yaml.safe_load(Path(a.plan).read_text())
    assignees = dict(x.split("=", 1) for x in a.assign)
    gh = GH(a.repo, a.dry_run)

    # ---- labels
    existing = {l["name"] for l in (gh.api("GET", "labels?per_page=100", paginate=True, allow_fail=a.dry_run) or [])}
    for l in plan["labels"]:
        if l["name"] in existing:
            gh.api("PATCH", f"labels/{l['name'].replace(':', '%3A')}", {"color": l["color"], "description": l["description"]})
        else:
            gh.api("POST", "labels", l)
    print(f"labels: {len(plan['labels'])} ok")

    # ---- milestones
    ms = {m["title"]: m["number"] for m in (gh.api("GET", "milestones?state=all&per_page=100", paginate=True, allow_fail=a.dry_run) or [])}
    ms_num = {}
    for m in plan["milestones"]:
        if m["title"] not in ms:
            ms[m["title"]] = gh.api("POST", "milestones", {"title": m["title"], "description": m["description"]})["number"]
        ms_num[m["key"]] = ms[m["title"]]
    print(f"milestones: {len(ms_num)} ok")

    # ---- existing issues by title
    issues = gh.api("GET", "issues?state=all&per_page=100", paginate=True, allow_fail=a.dry_run) or []
    by_title = {i["title"]: i for i in issues if "pull_request" not in i}

    def ensure_issue(title, body, labels, milestone=None, assignee=None):
        if title in by_title:
            return by_title[title]
        f = {"title": title, "body": body, "labels": labels}
        if milestone:
            f["milestone"] = milestone
        if assignee:
            f["assignees"] = [assignee]
        i = gh.api("POST", "issues", f)
        by_title[title] = i
        return i

    # ---- epics
    epics = {}
    for e in plan["epics"]:
        epics[e["key"]] = ensure_issue(e["title"], e["body"], ["epic", e["label"]], assignee=assignees.get(e["key"]))
        print(f"epic {e['key']}: #{epics[e['key']]['number']}")

    # ---- tasks (two passes so depends_on can reference issue numbers)
    tasks = plan["tasks"]
    epic_label = {e["key"]: e["label"] for e in plan["epics"]}
    created = {}
    for t in tasks:
        title = f"[{t['id']}] {t['title']}"
        labels = [epic_label[t["epic"]], f"size:{t['size']}"] + t.get("labels", [])
        body = t["body"] + f"\n\n---\nEpic: #{epics[t['epic']]['number']} · Milestone: {t['milestone']}"
        created[t["id"]] = ensure_issue(title, body, labels, ms_num[t["milestone"]], assignees.get(t["epic"]))

    for t in tasks:
        deps = t.get("depends_on", [])
        i = created[t["id"]]
        if deps:
            dep_line = "Depends on: " + ", ".join(f"#{created[d]['number']} ({d})" for d in deps)
            blocks = [x["id"] for x in tasks if t["id"] in x.get("depends_on", [])]
        else:
            dep_line = "Depends on: nothing - can start immediately."
            blocks = [x["id"] for x in tasks if t["id"] in x.get("depends_on", [])]
        block_line = ("Blocks: " + ", ".join(f"#{created[b]['number']} ({b})" for b in blocks)) if blocks else ""
        body = (t["body"] + f"\n\n---\nEpic: #{epics[t['epic']]['number']} · Milestone: {t['milestone']} · Size: {t['size']}\n"
                f"{dep_line}\n{block_line}").rstrip()
        gh.api("PATCH", f"issues/{i['number']}", {"body": body})
        # native sub-issue link (REST); ignore "already a sub-issue" errors on re-runs
        gh.api("POST", f"issues/{epics[t['epic']]['number']}/sub_issues", {"sub_issue_id": i["id"]}, allow_fail=True)
        print(f"  {t['id']} -> #{i['number']}")

    # ---- epic checklists
    for e in plan["epics"]:
        lines = [e["body"].rstrip(), "", "### Tasks"]
        for mkey in [m["key"] for m in plan["milestones"]]:
            ts = [t for t in tasks if t["epic"] == e["key"] and t["milestone"] == mkey]
            if ts:
                lines.append(f"**{mkey}**")
                lines += [f"- [ ] #{created[t['id']]['number']}" for t in ts]
        gh.api("PATCH", f"issues/{epics[e['key']]['number']}", {"body": "\n".join(lines)})
    print("done")


if __name__ == "__main__":
    main()
