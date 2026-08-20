"""Acquire one immutable daily input through the common connector contract."""

from __future__ import annotations

import argparse
import json
import sys
from datetime import date
from pathlib import Path
from typing import Any


SCRIPT_DIR = Path(__file__).resolve().parent
PROJECT_ROOT = SCRIPT_DIR.parents[2]
if str(PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(PROJECT_ROOT))

from shared.data.connectors.fixture import create_connector  # noqa: E402


def validate_business_date(value: str) -> str:
    parsed = date.fromisoformat(value)
    if parsed.isoformat() != value:
        raise ValueError("business date must use YYYY-MM-DD")
    return value


def acquire(*, business_date: str) -> dict[str, Any]:
    business_date = validate_business_date(business_date)
    connector = create_connector(PROJECT_ROOT / "shared" / "data" / "fixtures")
    health = connector.healthcheck()
    if health["status"] != "ready":
        raise RuntimeError("configured data connector is not ready")
    return connector.fetch(business_date=business_date)


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--business-date", required=True)
    args = parser.parse_args()
    print(json.dumps(acquire(business_date=args.business_date), ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
