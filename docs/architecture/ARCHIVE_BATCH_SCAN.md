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
- `POST /api/v1/scans` accepts `archive_mode` for archive uploads
  (ZIP, TAR family, 7z).
- Archive uploads create a `scan_batch` and a `container` scan before
  extraction is enabled.
- `lazy_extract_on_detection` extracts an archive after the container scan has
  a detection-risk verdict and enqueues extracted members as child scans, and
  applies the same rule recursively to detected children that are archives.

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

## Supported Formats

`app/services/archive_extractor.py` detects and extracts these formats through
one entry point, `extract_archive()`:

```text
zip   Python stdlib zipfile
tar   Python stdlib tarfile (tar, tar.gz/tgz, tar.bz2, tar.xz)
7z    py7zr (pure-Python dependency)
```

Format detection is `detect_archive_format()`; upload-time classification uses
`is_supported_archive()`. 7z and ZIP are magic-byte checks; TAR detection is
checksum-based and can false-positive on unlucky binaries, so it runs last.

Format-specific safety notes:

- ZIP: encrypted members are rejected explicitly.
- TAR: symlink, hardlink, device, and FIFO members are skipped; they carry no
  scannable payload, and members always stream into flat uuid-named sample
  files, never into their original paths.
- 7z: encrypted archives are rejected. Declared header sizes are validated
  first, and a custom writer factory re-enforces per-file and total byte
  limits on actual decompressed bytes, aborting mid-stream on a lying header
  (decompression-bomb defense).

RAR is intentionally not supported. Every Python RAR library shells out to an
external `unrar` binary that would have to be installed and version-managed on
each worker host (Docker and Windows) and has license restrictions. Revisit if
customer demand justifies the operational cost.

## Nested Archives

Lazy extraction is recursive: when a `child` scan is detected (or scores a
trigger verdict) and its sample is itself a supported archive, the worker
extracts it and enqueues grandchildren. Controls:

- `MASP_ARCHIVE_MAX_NESTED_LEVELS` (default 3) bounds archive-in-archive
  depth. The container is level 0; its children are level 1. When the limit is
  exceeded the worker records an `archive_nested_level_exceeded` event and
  creates nothing.
- The total number of `child` scans in one batch is capped by
  `MASP_ARCHIVE_MAX_FILES`. If an extraction would exceed the remaining
  budget, no children are created (partial fan-out would silently understate
  coverage) and an `archive_batch_child_limit_reached` event is recorded.
- Nested children keep the full path chain in `relative_path`, e.g.
  `payloads/inner.zip/bin/evil.exe`, and link to the nested archive scan via
  `parent_scan_id`.
- Clean children and non-archive children never expand.

## Safety Limits

Archive extraction must be bounded before it is enabled:

```text
MASP_ARCHIVE_MAX_FILES
MASP_ARCHIVE_MAX_TOTAL_BYTES
MASP_ARCHIVE_MAX_SINGLE_FILE_BYTES
MASP_ARCHIVE_MAX_DEPTH
MASP_ARCHIVE_MAX_NESTED_LEVELS
MASP_ARCHIVE_EXTRACT_ENABLED
```

The extractor must also reject unsafe paths:

- absolute paths
- `..` traversal
- drive-prefixed paths
- symlink/hardlink surprises across all archive formats

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
