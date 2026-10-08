# Profile rules

Status: agreed with the product owner on 2026-10-07 and implemented on `feat/archive-handling`.

## Why

A profile used to be an engine set plus a handful of policy fields (size limit,
content rule, masquerade, archive handling, review handling), each of which could
"inherit" a server or ICAP gateway setting. What actually happened to a file was the
combination of all of them, and the combination was not visible anywhere: a clean zip
blocked over ICAP while the profile said nothing about archives was the pilot's first
support call. Explaining the combination (a "what happens" table) made the screen
longer, not simpler.

The product owner asked for something else: policies that are simple and explicit,
with nothing forced by a hidden default, where different files can get different
engines, for example "above this many MB run these engines; when very large, only the
header and hash checks".

## The model

A profile is an ordered list of rules. A file takes the **first** rule it matches.

```
 #  When                              Do
 1  Size > 500 MB                     Light check: File Type, Hash List
 2  Size 50-500 MB                    Scan: ClamAV
 3  Type: program, script             Scan: ClamAV, Defender, YARA
 4  Type: archive                     Scan (open the archive, scan every file): ClamAV, Defender
 5  Extension contradicts content     Block
 6  Every other file                  Scan: ClamAV, Defender

 When the result is not conclusive:   Block
```

**Conditions** (all given conditions must match; a rule without conditions matches
everything): a size range in MB (from, up to), content types (any of the families
the header classifier knows), and "extension contradicts content".

**Actions**:

| Action | Engines | Outcome when nothing is found |
|---|---|---|
| Scan | chosen; at least one antivirus or other detection engine | Allow |
| Light check | chosen from the non-detection checks (File Type, Hash List, Static Metadata) | Allow, labelled **Light check only** |
| Allow without scanning | none | Allow, labelled **Not scanned** |
| Block | none | Block, listed as **Not allowed** (blocked by rule N) |

A Scan rule that can match archives also says how archives are treated: as one file,
opened and checked, or opened with every file inside scanned. An archive member is a
file of its own: it goes through the same rules by its own size and type.

**Nothing is implicit.** The last rule always matches every file and cannot be removed;
its action must be chosen. "When the result is not conclusive" must be chosen too:
Block, or Allow labelled **Not fully scanned**. A result is not conclusive when an
engine failed or did not finish, an engine asked for review, or the risk is elevated
without a detection. Profiles therefore never answer "review"; the API and ICAP see
allow or block.

Detections always win: a detection blocks whatever the rule says.

## Watched folders

A folder MASP reads itself (folder scanning) uses the rules of its profile too. Light check and
Block are applied while the folder is read; Allow without scanning is recorded as allowed; a
file a Scan rule matches waits until antivirus scanning of folders exists. See "Folders follow
profile rules" in `STORAGE_PROTECTION.md`.

## What stays outside the profile

Only what cannot be a per-file decision stays a deployment setting, and the profile
screen shows it read-only:

- the largest request the server or an ICAP gateway accepts (`MASP_UPLOAD_MAX_BYTES`
  ceiling, `MASP_ICAP_MAX_BYTES`): a larger file never reaches the rules;
- what an ICAP gateway does when MASP gives no verdict in time or cannot be reached
  (fail mode, `MASP_ICAP_WAIT_SECONDS`).

`MASP_ICAP_BLOCK_ARCHIVES` and `MASP_ICAP_BLOCK_ON_REVIEW` no longer apply to a rule
profile; its rules decide archives and inconclusive results.

## Recording and decisions

Intake evaluates the rules once, from the stored file's size and its 4 KiB header (the
shared `content_types.classify`), and freezes the result in the scan's routing snapshot:
`rule` holds the rule number and action, `engines` holds only that rule's engines and
`profile_engines` every engine any rule uses (archive members are evaluated against it).
Retries, coverage and decisions keep using the snapshot, as before.

A Block or Allow-without-scanning file still gets a scan record, completed at intake
with no engine jobs, so the ledger shows it; it cannot be retried. Decisions read
Allow (light check only), Allow (not scanned), Allow (not fully scanned) or Not
allowed: Blocked by rule N; the ledger and report badge Light check only, Not scanned
and Blocked by rule, and show incomplete coverage as before.
Recorded risk stays per file and is never raised by a rule.

Scans accepted under the previous policy format keep their previous decision logic: a
snapshot is never reinterpreted.

## Exceptions

Rules describe what happens to kinds of files; an exception is for one exact file an
administrator has confirmed is harmless (a false positive, a tool a user needs). It is kept
apart from the rules on purpose: the rules stay short, and every exception carries who added
it, why, and for how long.

- Keyed by the SHA-256 MASP computed itself, never a name, an extension or a digest a client
  supplied. A reason is required; an expiry is optional; one client or every client and
  manual scans. A client's own exception is used before one for all clients.
- Looked up once when a file is accepted and frozen in the routing snapshot (`exception`)
  and `scan_jobs.exception_id`, like the rule. Scans accepted earlier keep their decision,
  and revoking an exception does not change scans it already allowed.
- The rule still routes the file and its engines still run; their results are kept as
  evidence and recorded risk is unchanged. The decision is Allow (exception)
  (`exception_allow`) whatever the engines, the rule, the archive check or the policy said:
  a file a Block rule matches is allowed without scanning.
- No bell entry, no `malware.detected` and no `policy.not_allowed` SIEM event is raised for
  an excepted scan: it is not an incident.
- An archive member never inherits its container's exception; an excepted archive's
  decision does not depend on its members.
- The hash list's allowlist is a different thing: an informational finding that never
  allows a file.

Administrators manage exceptions on System > Exceptions (`/console/engines/exceptions`);
a flagged API ledger row ("Add exception") and a blocked or review report ("Add an
exception for this file") open the same dialog with the file and its client filled in, and
the ledger and report badge an excepted scan. Folder-scanning
findings are not covered by exceptions yet.

## Upgrading existing profiles

Each existing profile becomes the rule list that gives the same behaviour, in this
order: size limit -> Block above it; disguised extension -> Block; content denylist ->
Block those types; content allowlist -> Scan those types, Block every other file;
archive handling -> an archive rule; then every other file -> Scan with the profile's
engines. Behaviour that depended on a gateway setting is fixed at the value the gateway
used: a client that receives ICAP traffic gets "archive -> Block" when its archive
handling inherited the gateway (the gateway default refuses archives), and its review
handling becomes Allow, matching `MASP_ICAP_BLOCK_ON_REVIEW` off, unless its gateway
reported it on. A client without ICAP traffic keeps archives scanned as one file, and an
inherited review becomes Block, because "review" is no longer an answer.
