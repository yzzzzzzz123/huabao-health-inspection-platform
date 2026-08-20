"""Validate the tracked server contract and report a secret-free environment view."""

from __future__ import annotations

import argparse
import json
import platform
import subprocess
import sys
from pathlib import Path
from typing import Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.runtime_env import load_workspace_config, python_version_is_supported  # noqa: E402


def capture() -> dict[str, object]:
    config = load_workspace_config(PROJECT_ROOT)
    git = subprocess.run(
        ["git", "-C", str(PROJECT_ROOT), "rev-parse", "--show-toplevel"],
        cwd=PROJECT_ROOT,
        capture_output=True,
        text=True,
        shell=False,
        check=False,
    )
    return {
        "ok": python_version_is_supported() and git.returncode == 0,
        "python": platform.python_version(),
        "python_supported": python_version_is_supported(),
        "implementation": platform.python_implementation(),
        "platform": platform.platform(),
        "git_root_valid": git.returncode == 0,
        "config": config.public_projection(),
    }


def main(argv: Sequence[str] | None = None) -> int:
    argparse.ArgumentParser(description=__doc__).parse_args(argv)
    value = capture()
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))
    return 0 if value["ok"] else 1


if __name__ == "__main__":
    raise SystemExit(main())
