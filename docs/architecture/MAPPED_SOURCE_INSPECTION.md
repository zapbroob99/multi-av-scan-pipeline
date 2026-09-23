# Mapped-source inspection for large files

Status: **design draft for in-place inspection.** The bounded `file_type` header
adapter, multiple named profiles and client storage-access administration are
implemented within today's copy path. In-place reading and the local hash list
are not implemented. Sections marked **OPEN** remain unresolved.

## The use case

A consuming system uploads a very large file to its own storage. Scanning it
synchronously through MASP is not viable: the request would block, and MASP would
have to hold a full copy.

Instead MASP is *mapped* to the storage location and performs cheaper checks
there — content-type verification from magic bytes, a hash check against
institution-controlled lists, YARA rules, and size/extension policy — rather than
a full antivirus scan.

This is **eventual inspection, not preventive blocking**. The source application
may release the file before MASP reports. That constraint already applies to the
existing deferred path and does not change here.

## What already exists

The skeleton is in place. `POST /api/v1/deferred-scans` accepts metadata only and
returns `202`, carrying a client-scoped idempotency key, a deployment-approved
backend key and a relative object id. Raw URLs, UNC paths and arbitrary host
paths are rejected.

`app/services/deferred_storage.py` resolves an approved backend key to a
filesystem root from `MASP_DEFERRED_STORAGE_BACKENDS_JSON`, rejects traversal,
symlinks/junctions and hardlinks, and can scope a client to object prefixes so one
tenant cannot reference another tenant folder. Backend-to-client authorization is
explicit and fail-closed.

Routing already supports a lightweight profile: a service client profile can
assign only YARA and metadata engines, with no antivirus adapter. The immutable
routing snapshot records each engine `detection` and `required` flag, and
`required_detection_engine_names` derives coverage from that snapshot, so the
engine set is fixed at acceptance and a later edit cannot rewrite a completed
scan.

Two facts materially reduce the work:

- `resolve_sample_path()` in `app/services/sample_paths.py` uses
  `scan.storage_path` directly when it is a file. Engines are therefore **not**
  bound to the MASP samples directory; pointing that path at a mapped source is
  not a rewrite.
- The report layer already renders "No required detection engines configured —
  only metadata analyzers are assigned to this scan profile" rather than implying
  a clean verdict.

## What is missing

1. **In-place reading.** `copy_deferred_source()` copies every byte into MASP
   storage. For a large file this is exactly the cost the use case exists to
   avoid.
2. **Magic-byte inspection — implemented.** The separate `file_type` adapter
   reads a bounded header and reports declared-versus-actual content mismatch.
   `static_metadata` remains metadata-only. Neither adapter avoids the deferred copy.
3. **Local hash lists.** The only `supports_hash_lookup` adapter is VirusTotal,
   which is `support_state="blocked"`, consumes external quota and is excluded
   from API/ICAP by design. There is no institution-controlled blocklist or
   allowlist.
4. **Path execution mode.** `input_modes=("file", "path")` is declarative only.
   It appears in UI and routing metadata and drives nothing.
5. **Backend mapping in the UI — implemented.** Client Storage administration
   selects whole-backend or prefix access from deployment-approved logical keys.
   Per-client database grants replace environment grants only after confirmation;
   filesystem roots remain deployment-owned.

## Copying versus reading in place

Both approaches read the file. The difference is how many times, and how much
local disk is required. For a 50 GB source with magic-byte, hash and YARA checks:

| | Copy (today) | In place |
| --- | --- | --- |
| Read over the mount | 50 GB | 100 GB (hash, then YARA) |
| Write to local disk | 50 GB | none |
| Read from local disk | 50 GB (YARA) | none |
| Free local disk required | 50 GB | none |
| Total I/O | 150 GB | 100 GB |

Copying has an advantage that is easy to miss: it computes MD5/SHA-1/SHA-256
during its single copy pass, so the hash costs nothing extra. Reading in place
needs one pass for hashing and another for YARA, and both cross the slower mount.

The decisive factor is **which checks run**:

- **Magic bytes alone** need roughly the first 256 bytes. In place that is a
  256-byte read; copying first would move the whole file to inspect a header.
  This is the largest possible win and it exists only in place.
- **Hash or YARA** require a full read either way. In place then saves local disk
  and one write pass, not the read.

A single streaming pass that hashes and inspects magic bytes together reduces the
in-place total to one full read plus the YARA pass. Making YARA consume that same
stream would reduce it to one pass, but the YARA CLI takes a path rather than a
handle, so this would require buffer-based scanning with bounded memory.

**OPEN:** copy, in place, or a size-threshold hybrid. A hybrid keeps full copy
guarantees below the threshold and accepts weaker guarantees above it, at the cost
of two maintained code paths.

## Security boundaries

**A client-supplied hash is not a control.** The deferred API accepts
`expected_sha256`, and today it only verifies a copy MASP made itself. If a hash
check becomes a security decision, MASP must compute the digest from bytes it
read. A compromised or malicious client would otherwise supply the digest that
clears its own file. A client-supplied digest may *reject* a mismatch; it must
never *satisfy* a check.

**Time-of-check to time-of-use.** Copying closes this by comparing `fstat` before
and after against the open handle and failing on any size or timestamp change.
Reading in place weakens it: the YARA CLI receives a path, so the file can change
between validation and the engine open. Candidate mitigations, none yet chosen:

- Re-validate `fstat` after each engine and fail the scan on any change.
- Require the backend to expose an immutable or write-once view for mapped roots.
- Accept the weaker guarantee explicitly for this profile and record it in the
  result, so an operator never reads it as an atomic-source guarantee.

**OPEN:** which mitigation, and whether a changed source is a failure or a
recorded weaker outcome.

**Worker placement.** Only workers that mount the source root read-only can run
these engines. Worker pools with exact-match labels exist and engine instances can
be bound to them, but no rule expresses "this engine instance requires backend X".
Without it a scan can be claimed by a worker that cannot see the file and fails
late, rather than never being routed there.

**OPEN:** whether backend access becomes a first-class routing constraint or stays
an operational convention over existing pool labels.

## Result semantics

This is the part most likely to cause harm if we get it wrong.

The existing coverage model asks whether every **required detection** engine in
the snapshot completed. A lightweight profile containing YARA and a hash-list
adapter consists of detection engines, so a clean run reports full coverage —
technically accurate and operationally misleading, because no antivirus engine
ever ran.

The report must distinguish three states that today collapse into two:

1. Coverage complete for the engines that were **supposed** to run.
2. Coverage incomplete: an engine that should have run did not.
3. Coverage **deliberately narrow**: this profile never included antivirus.

State 3 must be visible in the report, the exports and the integration contract,
not only in profile configuration. The routing snapshot is the right home for it:
it is already immutable per scan and already carries engine identity and flags.

**OPEN:** whether this is an explicit profile classification (for example an
`inspection_only` flag in the snapshot) or derived from adapter categories. A
derived value is less configuration, but its meaning shifts silently when an
adapter category changes.

## Profile model

The use case needs per-client profiles of different weight: one client scanning
everything, another running inspection only. Multiple named profiles are now
implemented: client administration creates, renames, disables, deletes and chooses
a default; API requests can select an enabled profile owned by their client.
See `SERVICE_CLIENTS_AND_SCAN_PROFILES.md`. This supplies the routing prerequisite
only: deliberately narrow coverage semantics and in-place reading remain OPEN.

Backend access mapping now lives in client administration, with environment
inheritance for existing deployments. The console selects among deployment-approved
backend keys and never accepts or exposes a new filesystem root. See the storage
administration contract in `SERVICE_CLIENTS_AND_SCAN_PROFILES.md`.

**OPEN:** whether a mapped-source profile is a distinct profile kind or an ordinary
profile whose engine set happens to be lightweight. A distinct kind can carry the
inspection-only semantics above; an ordinary profile keeps one concept.

## Sequencing

Each step is independently useful and independently verifiable:

1. **Magic-byte inspection adapter.** Reads a bounded header, compares detected
   type against the declared one, reports a mismatch. Works with today's copy
   path, so it needs no storage change and no new security boundary.
2. **Local hash list adapter.** Institution-controlled blocklist/allowlist with
   list management in the console. MASP computes the digest itself.
3. **Multiple named profiles — implemented.** Client administration supports
   create, rename, delete and default selection, so a lightweight profile can
   exist beside a full one. This independent routing slice was completed before
   the local hash list; steps 2, 4 and 5 remain open.
4. **Result semantics.** Make deliberately narrow coverage explicit everywhere a
   decision is shown.
5. **In-place reading.** Only after 1-4, because it carries the security decisions
   and its value is clearest once the cheap checks exist.

Steps 1 and 2 deliver most of the product value while the copy path still provides
its guarantees. Step 5 is where the large-file saving actually lands, and it should
not be built first.

## Out of scope

Quarantine, deletion and any remediation on the source system. MASP reports; it
does not modify a source it was granted read-only access to.
