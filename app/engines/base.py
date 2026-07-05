from typing import Protocol

from app.models import EngineResultInput, ScanRecord


class EngineAdapter(Protocol):
    key: str

    def runtime_config(self, config_override: dict[str, str] | None = None) -> dict[str, object]:
        """Resolve adapter runtime settings for worker execution."""

    def health_check(self, config_override: dict[str, str] | None = None) -> dict[str, str | bool]:
        """Validate connectivity or local readiness before a scan runs."""

    def scan(self, scan: ScanRecord, config_override: dict[str, str] | None = None) -> EngineResultInput:
        """Run an engine against a stored sample and return normalized output."""
