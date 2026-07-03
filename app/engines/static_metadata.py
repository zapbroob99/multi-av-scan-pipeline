import json
from time import perf_counter

from app.models import EngineResultInput, ScanRecord


ENGINE_NAME = "Static Metadata"


def run_static_metadata_engine(scan: ScanRecord) -> EngineResultInput:
    started_at = perf_counter()
    metadata = {
        "scan_job_id": scan.id,
        "sample_id": scan.sample_id,
        "filename": scan.original_filename,
        "stored_filename": scan.stored_filename,
        "storage_path": scan.storage_path,
        "content_type": scan.content_type,
        "size_bytes": scan.size_bytes,
        "hashes": {
            "md5": scan.md5,
            "sha1": scan.sha1,
            "sha256": scan.sha256,
        },
    }
    duration_ms = max(1, int((perf_counter() - started_at) * 1000))

    return EngineResultInput(
        engine_name=ENGINE_NAME,
        engine_version="builtin",
        signature_version=None,
        status="completed",
        detected=False,
        signature=None,
        severity="info",
        confidence=100,
        raw_output=json.dumps(metadata, indent=2, sort_keys=True),
        error_message=None,
        duration_ms=duration_ms,
        details_json=json.dumps(metadata, sort_keys=True),
        findings_json="[]",
    )
