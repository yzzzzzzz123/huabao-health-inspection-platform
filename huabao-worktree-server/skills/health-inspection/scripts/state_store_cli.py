"""Read-only maintenance CLI for the Workspace Server SQLite index."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path
from typing import Any, Sequence


SCRIPT_DIR = Path(__file__).resolve().parent
SERVER_ROOT = SCRIPT_DIR.parents[2]
REPOSITORY_ROOT = SERVER_ROOT.parent
if str(SERVER_ROOT) not in sys.path:
    sys.path.insert(0, str(SERVER_ROOT))
if str(SCRIPT_DIR) not in sys.path:
    sys.path.insert(0, str(SCRIPT_DIR))

from state_store import StateStore  # noqa: E402


def _print(value: Any) -> None:
    print(json.dumps(value, ensure_ascii=False, indent=2, sort_keys=True))


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Inspect Workspace Server state")
    subparsers = parser.add_subparsers(dest="command", required=True)
    subparsers.add_parser("list")
    show = subparsers.add_parser("show")
    show.add_argument("run_id")
    events = subparsers.add_parser("events")
    events.add_argument("--run-id")
    subparsers.add_parser("integrity")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    arguments = build_parser().parse_args(argv)
    try:
        store = StateStore(REPOSITORY_ROOT)
        if arguments.command == "list":
            _print({"runs": store.list_runs()})
        elif arguments.command == "show":
            run = store.get_run(arguments.run_id)
            if run is None:
                _print({"ok": False, "error": "workspace_not_found"})
                return 1
            _print({"run": run, "artifacts": store.list_artifacts(arguments.run_id)})
        elif arguments.command == "events":
            _print({"events": store.list_events(run_id=arguments.run_id)})
        elif arguments.command == "integrity":
            _print(store.verify_integrity())
        return 0
    except Exception as exc:  # maintenance CLI boundary
        _print({"ok": False, "error": type(exc).__name__, "message": str(exc)})
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
