"""Stable read-only input contract shared by fixture and future API adapters."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Protocol


@dataclass(frozen=True)
class ConnectorMetadata:
    connector_id: str
    contract_version: str
    read_only: bool
    production_connected: bool


class DataConnector(Protocol):
    metadata: ConnectorMetadata

    def healthcheck(self) -> dict[str, Any]:
        """Return availability without exposing credentials."""

    def fetch(self, *, business_date: str) -> dict[str, Any]:
        """Return one immutable daily snapshot under the common contract."""
