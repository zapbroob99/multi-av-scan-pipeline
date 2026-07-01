from typing import Protocol

from app.models import EngineResultInput, ScanRecord


class EngineAdapter(Protocol):
    name: str

    def scan(self, scan: ScanRecord) -> EngineResultInput:
        """Run an engine against a stored sample and return normalized output."""
