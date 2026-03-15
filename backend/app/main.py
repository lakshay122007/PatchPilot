from __future__ import annotations

import os
import shutil
import tempfile
from pathlib import Path
from typing import Optional, Dict, Any, List

from fastapi import FastAPI, UploadFile, File, Form, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse

from .models import ScanResponse, Finding, FixRequest, FixResponse, VerifyResponse
from .scanners.semgrep import run_semgrep
from .scanners.osv import run_osv_scanner
from .scanners.gitleaks import run_gitleaks
from .remediation.engine import propose_fixes
from .sandbox.verify import verify_repo
from .reports.evidence_pack import build_evidence_pack
from .utils.fs import unzip_to_dir, safe_rmtree, ensure_dir

app = FastAPI(title="PatchPilot API", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # hackathon MVP
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

WORK_ROOT = Path(os.environ.get("PATCHPILOT_WORKDIR", Path(tempfile.gettempdir()) / "patchpilot"))
ensure_dir(WORK_ROOT)


@app.get("/health")
def health():
    return {"ok": True}


@app.post("/scan", response_model=ScanResponse)
async def scan(
    project: UploadFile = File(...),
    project_name: str = Form("project"),
):
    job_id = next(tempfile._get_candidate_names())
    job_dir = WORK_ROOT / job_id
    ensure_dir(job_dir)

    archive_path = job_dir / project.filename
    content = await project.read()
    archive_path.write_bytes(content)

    repo_dir = job_dir / "repo"
    ensure_dir(repo_dir)

    try:
        unzip_to_dir(archive_path, repo_dir)
    except Exception as e:
        safe_rmtree(job_dir)
        raise HTTPException(status_code=400, detail=f"Invalid zip upload: {e}")

    # run scanners
    semgrep = run_semgrep(repo_dir)
    osv = run_osv_scanner(repo_dir)
    gitleaks = run_gitleaks(repo_dir)

    findings: List[Finding] = []
    findings.extend(semgrep)
    findings.extend(osv)
    findings.extend(gitleaks)

    # naive prioritization score: severity + type weights
    def score(f: Finding) -> int:
        sev = {"CRITICAL": 100, "HIGH": 80, "MEDIUM": 50, "LOW": 20, "INFO": 5}.get(f.severity, 10)
        tw = {"dependency": 25, "secret": 35, "sast": 20}.get(f.category, 10)
        return sev + tw

    findings = sorted(findings, key=score, reverse=True)

    return ScanResponse(
        job_id=job_id,
        project_name=project_name,
        repo_path=str(repo_dir),
        findings=findings,
        scanners={
            "semgrep": {"ok": True, "count": len(semgrep)},
            "osv": {"ok": True, "count": len(osv)},
            "gitleaks": {"ok": True, "count": len(gitleaks)},
        },
    )


@app.post("/fix", response_model=FixResponse)
def fix(req: FixRequest):
    job_dir = WORK_ROOT / req.job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    fixes = propose_fixes(repo_dir, req.finding_ids)

    return FixResponse(job_id=req.job_id, fixes=fixes)


@app.post("/verify", response_model=VerifyResponse)
def verify(job_id: str = Form(...)):
    job_dir = WORK_ROOT / job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    result = verify_repo(repo_dir)
    return result


@app.post("/evidence-pack")
def evidence_pack(job_id: str = Form(...), project_name: str = Form("project")):
    job_dir = WORK_ROOT / job_id
    repo_dir = job_dir / "repo"
    if not repo_dir.exists():
        raise HTTPException(status_code=404, detail="Unknown job_id")

    out_dir = job_dir / "out"
    ensure_dir(out_dir)

    pack_path = build_evidence_pack(repo_dir=repo_dir, out_dir=out_dir, project_name=project_name, job_id=job_id)
    return FileResponse(path=str(pack_path), filename=pack_path.name, media_type="application/zip")


@app.delete("/jobs/{job_id}")
def delete_job(job_id: str):
    job_dir = WORK_ROOT / job_id
    if job_dir.exists():
        safe_rmtree(job_dir)
    return {"deleted": True}