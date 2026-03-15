from __future__ import annotations

import json
from pathlib import Path
from typing import List
from ..models import Finding, Location
from ..utils.exec import run_cmd


def run_gitleaks(repo_dir: Path) -> List[Finding]:
    cmd = ["gitleaks", "detect", "--no-git", "--redact", "--report-format", "json", "--report-path", "gitleaks.json"]
    r = run_cmd(cmd, cwd=repo_dir, timeout_s=600)

    report = repo_dir / "gitleaks.json"
    if not report.exists():
        if r["returncode"] != 0 and r["stderr"]:
            return [Finding(
                id="gitleaks:error",
                category="secret",
                severity="INFO",
                title="Gitleaks failed to run",
                description=r["stderr"][:5000],
            )]
        return []

    try:
        data = json.loads(report.read_text(encoding="utf-8") or "[]")
    except Exception:
        return []

    out: List[Finding] = []
    for item in data:
        rule = item.get("RuleID", "secret")
        path = item.get("File", "")
        start = item.get("StartLine")
        end = item.get("EndLine")
        desc = item.get("Description", "") or item.get("Match", "")
        out.append(Finding(
            id=f"gitleaks:{rule}:{path}:{start}",
            category="secret",
            severity="CRITICAL",
            title=f"Secret detected: {rule}",
            description=str(desc)[:1000],
            location=Location(path=path, start_line=start, end_line=end),
            metadata={"engine": "gitleaks", "rule": rule},
        ))
    return out