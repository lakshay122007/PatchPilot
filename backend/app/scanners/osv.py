from __future__ import annotations

import json
from pathlib import Path
from typing import List
from ..models import Finding
from ..utils.exec import run_cmd


def run_osv_scanner(repo_dir: Path) -> List[Finding]:
    # OSV-Scanner v2.x: JSON output is controlled by --format json under the `scan` command.
    cmd = ["osv-scanner", "scan", "--format", "json", "--recursive", "."]
    r = run_cmd(cmd, cwd=repo_dir, timeout_s=600)

    # osv-scanner may return nonzero if vulnerabilities found; still parse stdout if present
    if not r.get("stdout"):
        if r.get("stderr"):
            return [Finding(
                id="osv:error",
                category="dependency",
                severity="INFO",
                title="OSV-Scanner failed to run",
                description=r["stderr"][:5000],
                metadata={"cmd": cmd, "returncode": r.get("returncode")},
            )]
        return []

    try:
        data = json.loads(r["stdout"])
    except Exception:
        return [Finding(
            id="osv:error",
            category="dependency",
            severity="INFO",
            title="OSV-Scanner output was not valid JSON",
            description=(r.get("stdout", "")[:2000] + "\n" + r.get("stderr", "")[:2000])[:5000],
            metadata={"cmd": cmd, "returncode": r.get("returncode")},
        )]

    out: List[Finding] = []
    results = data.get("results", []) or []
    for res in results:
        packages = res.get("packages", []) or []
        for pkg in packages:
            vulns = pkg.get("vulnerabilities", []) or []
            for v in vulns:
                vuln_id = v.get("id", "OSV-UNKNOWN")
                out.append(Finding(
                    id=f"osv:{vuln_id}:{(pkg.get('package', {}) or {}).get('name','pkg')}",
                    category="dependency",
                    severity="HIGH",
                    title=f"Dependency vulnerability {vuln_id}",
                    description=(v.get("summary") or v.get("details") or "")[:1000],
                    location=None,
                    metadata={
                        "osv_id": vuln_id,
                        "package": pkg.get("package"),
                        "affected": v.get("affected"),
                        "references": v.get("references"),
                        "engine": "osv-scanner",
                        "cmd": cmd,
                        "returncode": r.get("returncode"),
                    },
                ))
    return out