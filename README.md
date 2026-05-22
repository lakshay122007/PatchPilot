# PatchPilot

PatchPilot is a lightweight security scanning and remediation MVP that lets you upload a codebase (ZIP) or import a GitHub repository URL, run multiple security scanners, and generate an evidence pack for reporting/compliance.

What it does:

- **Scan**: run SAST + dependency + secret scanning
- **Fix**: propose remediations for selected findings
- **Verify**: run verification checks in a sandboxed workflow
- **Evidence Pack**: export a ZIP containing audit artifacts and diffs

## Features

- Upload a **ZIP** codebase and scan it
- Import a **GitHub repository URL** and scan it (server-side download)
- Aggregates findings from:
  - **Semgrep** (SAST)
  - **OSV-Scanner** (dependency vulnerabilities)
  - **Gitleaks** (secret detection)
- Simple prioritization/sorting by severity + category
- Generate an **Evidence Pack** ZIP (audit trail)
- Frontend UI built with **React + Vite + Tailwind**

## Repository Structure

- `backend/` — FastAPI API server
- `frontend/` — React/Vite web UI

## API Routes (Backend)

- `GET /health` — health check
- `POST /scan` — upload ZIP and scan  
  **FormData**: `project` (file), `project_name` (optional)
- `POST /scan-url` — import GitHub repo URL and scan  
  **FormData**: `repo_url`, `ref` (optional, default `main`), `project_name` (optional)
- `POST /fix` — generate proposed fixes  
  **JSON**: `{ "job_id": "...", "finding_ids": ["..."] }`
- `POST /verify` — verify repository  
  **FormData**: `job_id`
- `POST /evidence-pack` — build evidence pack ZIP  
  **FormData**: `job_id`, `project_name` (optional)
- `DELETE /jobs/{job_id}` — delete job workspace

## Prerequisites

### Backend

- Python 3.10+ recommended
- CLI tools available on `PATH`:
  - `semgrep`
  - `osv-scanner`
  - `gitleaks`

> Note: If `osv-scanner` can’t find any supported dependency manifests/lockfiles, it may produce no dependency findings.

### Frontend

- Node.js 18+ recommended
- npm (or pnpm/yarn)

## Setup & Run

### 1) Backend

```bash
cd backend

python -m venv .venv
# Windows:
.venv\Scripts\activate
# macOS/Linux:
source .venv/bin/activate

pip install -r requirements.txt

# Run FastAPI (default: http://localhost:8000)
uvicorn app.main:app --reload --port 8000
```

### 2) Frontend

```bash
cd frontend
npm install

# Point frontend to backend (optional if default is localhost:8000)
# create/edit frontend/.env:
# VITE_API_BASE_URL=http://localhost:8000

npm run dev
```

Open the UI at the Vite dev server URL (commonly `http://localhost:5173`).

## Usage

1. Go to **Dashboard**
2. Choose one:
   - **Browse Files** → upload a ZIP
   - **Import from URL** → paste a GitHub repo URL
3. View results in **Findings**
4. Go to **Verify** to generate and download an **Evidence Pack**
