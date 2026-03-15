from __future__ import annotations

import os
import subprocess
from pathlib import Path
from typing import List


class CmdResult(dict):
    pass


def run_cmd(cmd: List[str], cwd: Path, timeout_s: int = 300) -> CmdResult:
    env = os.environ.copy()
    # Force UTF-8 so tools like semgrep don't crash on Windows cp1252.
    env.setdefault("PYTHONUTF8", "1")
    env.setdefault("PYTHONIOENCODING", "utf-8")

    try:
        p = subprocess.run(
            cmd,
            cwd=str(cwd),
            capture_output=True,
            text=True,
            timeout=timeout_s,
            env=env,
        )
        return CmdResult(
            cmd=cmd,
            returncode=p.returncode,
            stdout=p.stdout,
            stderr=p.stderr,
            ok=True,
        )
    except OSError as e:
        return CmdResult(
            cmd=cmd,
            returncode=127,
            stdout="",
            stderr=str(e),
            ok=False,
            os_error=getattr(e, "winerror", None),
        )
    except subprocess.TimeoutExpired as e:
        return CmdResult(
            cmd=cmd,
            returncode=124,
            stdout=getattr(e, "stdout", "") or "",
            stderr=f"TimeoutExpired: {e}",
            ok=False,
        )