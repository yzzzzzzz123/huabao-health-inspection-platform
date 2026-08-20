"""Read-only evidence queries over an API-supplied evidence catalog."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any


def query(
    catalog: dict[str, Any],
    *,
    command: str,
    value: str | None = None,
) -> Any:
    evidence = list(catalog.get("evidence", []))
    if command == "list":
        return [
            {
                key: item[key]
                for key in (
                    "evidence_id",
                    "kind",
                    "title",
                    "source",
                    "scope",
                    "observed_at",
                )
            }
            for item in evidence
        ]
    if command == "get":
        matches = [item for item in evidence if item.get("evidence_id") == value]
    elif command == "metric":
        matches = [
            item
            for item in evidence
            if item.get("payload", {}).get("metric_id") == value
        ]
    elif command == "related":
        matches = [
            item
            for item in evidence
            if value in item.get("payload", {}).get("related_ids", [])
        ]
    else:
        raise ValueError(f"unsupported evidence command: {command}")
    if command == "get":
        if len(matches) != 1:
            raise KeyError(f"evidence ID not found: {value}")
        return matches[0]
    return matches


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("list", "get", "metric", "related"))
    parser.add_argument("--id")
    args = parser.parse_args()
    catalog = json.load(sys.stdin)
    if not isinstance(catalog, dict):
        raise SystemExit("catalog must be a JSON object")
    result = query(catalog, command=args.command, value=args.id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
