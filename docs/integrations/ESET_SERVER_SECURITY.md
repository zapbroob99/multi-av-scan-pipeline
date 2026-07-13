# ESET Server Security for Linux Integration (Stage A: research)

This document describes the MASP adapter for ESET Server Security for Linux via
its on-demand command-line scanner, `odscan`, and the two-stage plan for taking
it from a binary-free skeleton to a corporate-validated engine.

**Support state: `research`.** The adapter is NOT validated against a real ESET
install and MUST NOT be treated as supported or production-ready until Stage B
is complete. It is disabled on add and never joins scan routing until an
operator explicitly enables it.

## Why a CLI adapter (not ICAP)

MASP's ICAP gateway is how MASP is *consumed* (storage client → MASP). ESET is a
scan *engine*, integrated like Microsoft Defender: a per-host worker shells out
to a local scanner. ESET Server Security for Linux ships `odscan`, so the same
worker-capability split MASP already uses applies — one worker advertises the
`eset_server_security_linux_cli` engine key and runs on the ESET host.

Note: user-endpoint ESET (Endpoint Antivirus, `ecls.exe` on Windows) is a
different product with a different CLI contract. This integration is Linux
Server Security only. A Windows endpoint path would be a separate future phase.

## Stage A — external development (no ESET binary required)

Delivered in this branch, all binary-free:

- `app/engines/eset_server_security_linux.py` — the adapter.
- Registered as `eset_server_security_linux_cli` (disabled on add, Linux only).
- `tools/eset_discovery.py` — read-only discovery tool.
- `install-masp-eset-worker.sh` — idempotent worker bootstrap.
- `MASP_SAMPLE_PATH_MAPPINGS_JSON` — VM storage mount mapping.
- Focused mock tests.

### Exit-code contract (official ESET Linux `odscan`)

| Exit | Meaning | MASP result |
|---|---|---|
| 0 | no threat found | `completed`, clean |
| 1 | threat found and cleaned | `completed`, **detected** + warning (unexpected under `--readonly`) |
| 10 | some files could not be scanned | `failed` (unscannable — **never** clean) |
| 50 | threat found | `completed`, **detected** |
| 100 | error | `failed` |
| other | unknown | `failed` |

Scan command: `odscan --scan --readonly --ignore-exclusions <path>`.
- `--readonly`: scan only, never clean/quarantine, so MASP's stored sample is
  left byte-for-byte intact.
- `--ignore-exclusions`: do not honor ESET central-policy exclusions during the
  scan, so an organization exclusion cannot cause MASP to report a scanned file
  "clean". This is **on by default** and can be disabled with the
  `eset_server_security_linux_cli.ignore_exclusions=false` setting. **Disabling
  it is a security downgrade**: a policy exclusion could then produce a false
  clean verdict. Only disable it with a documented reason and compensating
  control.

**FIXTURE-PENDING:** `--ignore-exclusions` is treated as fail-safe — if a build
does not support the flag, the scan errors out (mapped to `failed`) rather than
returning a false clean. Stage B confirms flag support from the discovery tool's
`--help` capture before this is relied on. Threat-name / output text parsing is
intentionally minimal.
Detections report a generic signature until a sanitized fixture from Stage B
confirms `odscan`'s real output format. Do not add speculative parsing.

### Health contract (Stage A)

Health is `ok` if and only if the `odscan` executable exists (definitive).
The adapter performs no version/help subprocess on the per-scan hot path.
Best-effort probes live only in the discovery tool; their failure does not mark
the engine unusable. The production health contract is finalized in Stage B.

### Configuration

`executable_path` resolves in order: DB setting
`eset_server_security_linux_cli.executable_path` → `MASP_ODSCAN_PATH` env
(written by the worker bootstrap) → `auto` (probes `/opt/eset/efs/bin/odscan`,
then `PATH`). Other settings: `eset_server_security_linux_cli.timeout_seconds`,
`eset_server_security_linux_cli.ignore_exclusions` (default `true`). There is no
admin-UI config form in Stage A (deferred to Stage B).

### Sample path mapping (VM mount)

When the ESET worker runs in a VM that mounts MASP storage at a different path
than the DB-stored prefix, set `MASP_SAMPLE_PATH_MAPPINGS_JSON`:

```json
{"/app/storage/samples": "/mnt/masp-storage/samples"}
```

- The value is a JSON object of `source_prefix → absolute target root`.
- A malformed value raises an explicit configuration error (no silent
  fallback).
- For Stage B discovery and simple-file validation, the mount may be
  **read-only**: `odscan --readonly` does not modify the sample.
- Production lazy-archive behavior is different: whichever engine worker
  finalizes a detected archive may extract child files. Today that can be the
  ESET worker, and extraction must write the children to storage shared with
  every other worker. A VM-local destination would create DB rows whose files
  the other workers cannot read.
- Therefore do not claim production readiness with a permanently read-only ESET
  mount. Before production, either provide the same shared writable storage to
  the ESET worker or implement explicit archive-finalizer ownership/centralized
  extraction. The latter is preferred for least privilege and remains a Stage B
  architecture decision.
- Path resolution rejects `..` traversal, absolute-path injection, and symlinks
  that escape the target root.

## Stage B — corporate validation (requires ESET + license)

**Phase 0 precondition (blocker):** confirm with IT which ESET product and
license the organization holds, and that using it on a scan server is within
the license terms. ESET Server Security for **Linux** is the target; an
Endpoint-only license does not cover this server integration. Do not start
Stage B provisioning until this is confirmed.

### Steps

1. On an approved Linux VM in the corporate test network, install ESET Server
   Security for Linux (separately — the bootstrap script does not install or
   license ESET).
2. Deploy the same MASP release/commit to the VM (see Release packaging below).
3. Prepare the ESET PROTECT policy (see "PROTECT policy model" below) BEFORE
   scanning any test file.
4. Provision the worker (the script never takes the DB password on the command
   line):
   ```bash
   sudo ./install-masp-eset-worker.sh --dry-run   # review
   sudo ./install-masp-eset-worker.sh             # provision
   sudoedit /etc/masp/eset-worker.env             # fill in MASP_DATABASE_URL etc.
   sudo ./install-masp-eset-worker.sh             # re-run: post-install checks now pass
   ```
   The worker runs as the unprivileged `masp-eset` user; the env file is
   `root:root 0600`, read by systemd (pid 1) and passed to the service. The
   bootstrap preserves existing values, restores ownership/mode on every run,
   and parses health-check values as data rather than sourcing the file as shell
   code. Post-install checks use a privilege-dropping wrapper with a minimal
   environment; the DB secret is inherited by the child and never placed in
   command-line arguments.
5. Run **inventory** discovery first (no scanning). Confirm from the captured
   `--help` output that `--ignore-exclusions` is supported before relying on it:
   ```bash
   ./.venv/bin/python tools/eset_discovery.py --output inventory.json
   ```
6. With security-team approval, scan controlled test files (clean / EICAR /
   unscannable / timeout) in the **dedicated staging directory** (see policy
   model):
   ```bash
   ./.venv/bin/python tools/eset_discovery.py --scan-sample /srv/eset-staging/eicar.com --yes --output eicar.json
   ```
   The tool records exit code, redacted output, wall-clock duration, and
   `sha256_before`/`sha256_after`/`file_changed`/`file_missing_after_scan`. A
   changed or missing file means ESET real-time protection acted on it —
   fix the policy exclusion scope before trusting further results.
7. Manually review every discovery JSON before it leaves the corporate network.
   Redaction (hostname, username, IPs, home paths, sample path, non-standard
   executable path) is best-effort, not a guarantee. Standard ESET install
   paths are intentionally preserved.
8. Bring the sanitized JSONs back to development. Complete the real fixture,
   finalize the output/threat-name parser and the version/health contract.
9. Only then run the ESET worker end-to-end, verify coverage, and benchmark.
   Include a detected archive whose children must be scanned by another worker,
   and verify that every child path is readable across workers. Do not mark the
   adapter `supported`/production-ready until this passes and the archive storage
   decision above is closed.

### ESET PROTECT policy model

Manage this VM through ESET PROTECT with least-privilege, scoped configuration —
not machine-local ad-hoc exclusions:

- Put the VM in a **dedicated static group** in ESET PROTECT, separate from
  production endpoints.
- Assign a **dedicated policy** to that group only. Do not edit a shared/parent
  policy.
- In that policy, scope the real-time protection exclusion to **only** the
  staging directory (e.g. `/srv/eset-staging/`). **Never grant a global
  exclusion** and never widen it to MASP's storage mount.
- Verify the **effective policy** actually applied to the VM in PROTECT (merged
  result of all assigned policies), not just the policy you authored — a parent
  or higher-priority policy can override it.
- On-demand MASP scans run `--ignore-exclusions`, so they bypass policy
  exclusions and scan the file regardless. The staging exclusion exists only to
  stop *real-time* protection from quarantining the sample before the on-demand
  scan runs; the on-demand result itself is not weakened.

### EICAR / real-time protection caveat

Even though the discovery tool and `icap_probe.py --eicar` can generate EICAR in
memory, MASP writes the ICAP upload to its storage area and `odscan` requires a
file path — so the sample is on disk. In a real environment ESET real-time
protection may quarantine it before the scan. The dedicated-policy staging
exclusion above prevents that for the staging directory only; rely on the
SHA-256 before/after check to detect any tampering.

## Release packaging (dev → corporate, offline)

No new packaging infrastructure — use `git archive` from a tagged commit:

```bash
git archive --format=zip --output masp-<commit>.zip <commit>
sha256sum masp-<commit>.zip > masp-<commit>.zip.sha256   # Linux
# or, on Windows dev:  Get-FileHash masp-<commit>.zip -Algorithm SHA256
```

Carry the zip, its SHA-256, `requirements.txt`, and this runbook. Do not include
ESET installers, binaries, licenses, or malware samples in the repo or package.
