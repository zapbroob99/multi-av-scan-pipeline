# MASP Archive Batch Scan Architecture

This document describes the foundation for archive and folder-style scanning in
MASP. The goal is to support uploads such as ZIP files without turning the
existing scan queue into an opaque "one request did many things" flow.

The important distinction:

- A normal uploaded file is still one `sample`, one `scan_job`, and one set of
  `scan_engine_jobs`.
- An archive upload may become a `scan_batch` with a container scan and many
  child scans.
- Batch metadata should not slow down standalone manual/API scans. It is
  nullable metadata on `scan_jobs` until archive mode is explicitly used.

## Current Foundation

Implemented foundation:

- `scan_batches` table for archive-level grouping.
- `scan_jobs.batch_id` to associate scans with a batch.
- `scan_jobs.parent_scan_id` to link child scans to the container scan.
- `scan_jobs.relative_path` to preserve the path inside the uploaded archive.
- `scan_jobs.scan_role` to distinguish standalone, container, and child scans.
- `POST /api/v1/scans` accepts `archive_mode` for ZIP uploads.
- ZIP uploads create a `scan_batch` and a `container` scan before extraction is
  enabled.
- `lazy_extract_on_detection` extracts a ZIP after the container scan has a
  detection-risk verdict and enqueues extracted members as child scans.

Scan roles:

```text
standalone
container
child
```

Existing scans default to:

```text
batch_id = NULL
parent_scan_id = NULL
relative_path = NULL
scan_role = standalone
```

That means the existing non-archive manual and API single-file flow stays:

```text
UploadFile
  -> store_upload()
  -> samples
  -> scan_jobs(scan_role=standalone)
  -> scan_engine_jobs
  -> workers
  -> engine_results
```

## Why Batches Exist

Archives are not just large files. They can contain many independently
interesting files. If MASP only scans the uploaded ZIP as one sample, it can
answer:

```text
Was this ZIP detected by any enabled engine?
```

It cannot reliably answer:

```text
Which inner file was detected?
What was the SHA256 of that inner file?
Should this inner file be excluded next time?
How many files were clean, failed, skipped, or suspicious?
Which relative path produced the detection?
```

The batch model gives MASP a durable parent object for those answers.

## Scan Roles

`standalone` is the existing behavior. It is used for ordinary manual uploads
and ordinary API uploads.

`container` is the uploaded archive itself. Engines scan the archive file as a
single sample. This mode is cheap and preserves AV-native archive handling, but
it does not provide per-file child results.

`child` is a file extracted from the archive. Each child is stored as a normal
sample and scanned through the same engine-job queue as every other scan.

The intended relationship looks like this:

```text
scan_batches #42 bundle.zip
  scan_jobs #100 scan_role=container relative_path=bundle.zip
  scan_jobs #101 scan_role=child     relative_path=docs/readme.txt
  scan_jobs #102 scan_role=child     relative_path=bin/tool.exe
```

## API Modes

The public API exposes archive behavior explicitly:

```text
archive_mode=container
archive_mode=lazy_extract_on_detection
archive_mode=container_and_extracted
```

Currently implemented API modes:

```text
container
lazy_extract_on_detection
```

`lazy_extract_on_detection` is the default. It scans the archive as a container
first. MASP extracts and creates child scans only if the container scan has a
detection or a risk verdict of `medium`, `high`, or `critical`. This avoids
expanding clean archives while still preserving the path toward per-file
visibility when the container looks interesting.

`container` forces container-only behavior. It keeps upload behavior predictable
and never creates child scans.

`container_and_extracted` is planned but intentionally not exposed yet. It should
be opt-in. It creates the container scan and then creates child scans for
extracted files within configured safety limits.

For non-archive uploads, MASP should ignore archive extraction and keep the scan
as `standalone`.

MASP's external upload contract should stay file-based:

```text
single file upload -> standalone scan
archive file upload -> archive scan
multiple files or folders -> client packages them as ZIP first
```

The server should not accept a raw folder as the durable upload unit. A folder
path is not portable across API clients, Docker volumes, Windows workers, and
distributed worker nodes. Packaging folder-like uploads as a ZIP preserves the
original container, relative paths, and audit trail as one sample.

## Performance Model

Batch metadata itself is cheap. Adding nullable columns such as `batch_id` and
`scan_role` does not materially affect standalone scan runtime when the right
indexes exist.

The expensive part is child scan fan-out:

```text
1 ZIP with 1,000 files
  -> 1 container scan
  -> up to 1,000 child scans
  -> each child creates one engine job per enabled engine
```

So the performance cost is not "batch support." The cost is doing real work for
many extracted files.

For throughput planning, the unit of work remains an engine job:

```text
child file count * enabled engine count
```

The existing engine-job queue is the correct execution path because different
workers can claim compatible engine jobs independently.

## Safety Limits

Archive extraction must be bounded before it is enabled:

```text
MASP_ARCHIVE_MAX_FILES
MASP_ARCHIVE_MAX_TOTAL_BYTES
MASP_ARCHIVE_MAX_SINGLE_FILE_BYTES
MASP_ARCHIVE_MAX_DEPTH
MASP_ARCHIVE_EXTRACT_ENABLED
```

The extractor must also reject unsafe paths:

- absolute paths
- `..` traversal
- drive-prefixed paths
- symlink/hardlink surprises when future archive formats are added

ZIP should be the first supported format because Python's `zipfile` gives MASP
a structured standard-library parser and avoids shelling out to external tools.

## UI Model

Manual scan UI should stay optimized for analyst inspection. It should default
to the existing single-file behavior and later offer a deliberate "deep archive"
mode.

API Ledger should not render every child scan in the main table. For large API
loads, the ledger should show a batch row or batch link, then a paginated batch
detail page for child scans.

The dashboard split should be:

```text
Manual dashboard:
  human-friendly scan details for manual uploads

API ledger:
  high-volume request history, raw status/result links, batch drill-down
```

## Implementation Sequence

Recommended sequence:

1. Add batch schema, records, and basic DB helpers.
2. Add architecture docs and tests for standalone/container/child metadata.
3. Add ZIP-only archive detection and extraction service.
4. Add `archive_mode` to `POST /api/v1/scans` and create container scans for ZIP uploads.
5. Add `lazy_extract_on_detection` finalization hook after container verdicts are available.
6. Add batch status/result endpoints.
7. Add API Ledger batch drill-down with pagination.
8. Add manual "deep archive scan" control after the API path is stable.

This sequence keeps normal scans stable while archive behavior is built in
visible, testable layers.

Steps 1-5 are implemented. Steps 6-8 are the next UI/API layers.
