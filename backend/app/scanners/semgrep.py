from __future__ import annotations

import json
from pathlib import Path
from typing import List
from ..models import Finding, Location
from ..utils.exec import run_cmd

SEMGRP_CONFIG = "p/ci"  # safe default ruleset


def run_semgrep(repo_dir: Path) -> List[Finding]:
    cmd = ["semgrep", "--config", SEMGRP_CONFIG, "--json", "--quiet"]
    r = run_cmd(cmd, cwd=repo_dir, timeout_s=600)

    if r["returncode"] not in (0, 1):  # semgrep uses 1 for findings sometimes
        return [Finding(
            id="semgrep:error",
            category="sast",
            severity="INFO",
            title="Semgrep failed to run",
            description=r["stderr"][:5000],
        )]

    try:
        data = json.loads(r["stdout"] or "{}")
    except Exception:
        return []

    out: List[Finding] = []
    for res in data.get("results", []) or []:
        check_id = res.get("check_id", "semgrep:unknown")
        path = res.get("path")
        start = (res.get("start") or {}).get("line")
        end = (res.get("end") or {}).get("line")
        msg = (res.get("extra") or {}).get("message", "")
        severity = ((res.get("extra") or {}).get("severity") or "INFO").upper()

        out.append(Finding(
            id=f"semgrep:{check_id}:{path}:{start}",
            category="sast",
            severity=severity if severity in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO") else "INFO",
            title=check_id,
            description=msg,
            location=Location(path=path, start_line=start, end_line=end),
            metadata={"check_id": check_id, "engine": "semgrep"},
        ))
    return out