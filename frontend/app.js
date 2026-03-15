const API = localStorage.getItem("PATCHPILOT_API") || "http://127.0.0.1:8000";
document.getElementById("apiUrl").textContent = API;

let currentJobId = null;
let currentFindings = [];

function el(tag, attrs = {}, children = []) {
  const n = document.createElement(tag);
  Object.entries(attrs).forEach(([k, v]) => (n[k] = v));
  children.forEach((c) => n.appendChild(c));
  return n;
}

function renderFindings(findings) {
  const wrap = document.getElementById("findings");
  wrap.innerHTML = "";

  if (!findings.length) {
    wrap.textContent = "No findings.";
    return;
  }

  findings.forEach((f) => {
    const cb = el("input", { type: "checkbox", className: "sel", value: f.id });
    const title = `${f.severity} • ${f.category} • ${f.title}`;
    const loc = f.location
      ? `${f.location.path}:${f.location.start_line || ""}`
      : "";
    const row = el("div", { className: "finding" }, [
      cb,
      el("div", { className: "ftext" }, [
        el("div", { className: "ftitle", textContent: title }),
        el("div", {
          className: "fdesc",
          textContent: (f.description || "").slice(0, 240),
        }),
        el("div", { className: "floc", textContent: loc }),
      ]),
    ]);
    wrap.appendChild(row);
  });
}

function selectedFindingIds() {
  return Array.from(document.querySelectorAll("input.sel:checked")).map(
    (n) => n.value,
  );
}

document.getElementById("scanBtn").onclick = async () => {
  const file = document.getElementById("zip").files[0];
  const projectName = document.getElementById("projectName").value || "project";
  if (!file) return alert("Upload a ZIP first.");

  const fd = new FormData();
  fd.append("project", file);
  fd.append("project_name", projectName);

  const res = await fetch(`${API}/scan`, { method: "POST", body: fd });
  const data = await res.json();
  if (!res.ok) return alert(JSON.stringify(data));

  currentJobId = data.job_id;
  currentFindings = data.findings || [];

  document.getElementById("job").textContent =
    `Job: ${currentJobId} • Findings: ${currentFindings.length}`;
  renderFindings(currentFindings);

  document.getElementById("fixBtn").disabled = false;
  document.getElementById("verifyBtn").disabled = false;
  document.getElementById("evidenceBtn").disabled = false;
};

document.getElementById("fixBtn").onclick = async () => {
  const ids = selectedFindingIds();
  if (!ids.length) return alert("Select findings to fix/suggest.");

  const res = await fetch(`${API}/fix`, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({ job_id: currentJobId, finding_ids: ids }),
  });
  const data = await res.json();
  document.getElementById("fixOut").textContent = JSON.stringify(data, null, 2);
};

document.getElementById("verifyBtn").onclick = async () => {
  const fd = new FormData();
  fd.append("job_id", currentJobId);
  const res = await fetch(`${API}/verify`, { method: "POST", body: fd });
  const data = await res.json();
  document.getElementById("verifyOut").textContent = JSON.stringify(
    data,
    null,
    2,
  );
};

document.getElementById("evidenceBtn").onclick = async () => {
  const projectName = document.getElementById("projectName").value || "project";
  const fd = new FormData();
  fd.append("job_id", currentJobId);
  fd.append("project_name", projectName);

  const res = await fetch(`${API}/evidence-pack`, { method: "POST", body: fd });
  if (!res.ok) {
    const data = await res.json().catch(() => ({}));
    return alert(JSON.stringify(data));
  }
  const blob = await res.blob();
  const url = URL.createObjectURL(blob);
  const a = document.createElement("a");
  a.href = url;
  a.download = `patchpilot_evidence_${projectName}_${currentJobId}.zip`;
  a.click();
  URL.revokeObjectURL(url);
};
