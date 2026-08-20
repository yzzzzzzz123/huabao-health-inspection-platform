"""Read-only queries over one immutable API-supplied health policy."""

from __future__ import annotations

import argparse
import json
import sys
from typing import Any

from policy_store import policy_runtime_gate_projection, validate_frozen_policy


def query(
    policy: dict[str, Any],
    *,
    command: str,
    metric_id: str | None = None,
) -> Any:
    frozen = validate_frozen_policy(policy)
    if command == "summary":
        return policy_runtime_gate_projection(frozen)
    if command == "list":
        return list(frozen["rules"])
    if command == "metric":
        matches = [
            item for item in frozen["rules"] if item["metric_id"] == metric_id
        ]
        if len(matches) != 1:
            raise KeyError(f"metric policy not found: {metric_id}")
        return matches[0]
    raise ValueError(f"unsupported policy command: {command}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=("summary", "list", "metric"))
    parser.add_argument("--id")
    args = parser.parse_args()
    policy = json.load(sys.stdin)
    if not isinstance(policy, dict):
        raise SystemExit("policy must be a JSON object")
    result = query(policy, command=args.command, metric_id=args.id)
    print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
