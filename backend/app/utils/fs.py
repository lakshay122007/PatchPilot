from __future__ import annotations

import os
import shutil
import zipfile
from pathlib import Path


def ensure_dir(p: Path) -> None:
    p.mkdir(parents=True, exist_ok=True)


def safe_rmtree(p: Path) -> None:
    shutil.rmtree(p, ignore_errors=True)


def unzip_to_dir(zip_path: Path, out_dir: Path) -> None:
    with zipfile.ZipFile(zip_path, "r") as z:
        z.extractall(out_dir)

    # If zip contains a single top-level folder, flatten it for nicer paths
    children = list(out_dir.iterdir())
    if len(children) == 1 and children[0].is_dir():
        top = children[0]
        tmp = out_dir.parent / (out_dir.name + "_tmp")
        tmp.mkdir(parents=True, exist_ok=True)
        for item in top.iterdir():
            shutil.move(str(item), str(tmp / item.name))
        shutil.rmtree(top)
        for item in tmp.iterdir():
            shutil.move(str(item), str(out_dir / item.name))
        shutil.rmtree(tmp)