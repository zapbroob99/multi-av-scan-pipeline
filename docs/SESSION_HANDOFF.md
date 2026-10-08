# MASP session handoff

Updated: 2026-10-08, pilot.17 (profile rules, folder rules, exceptions, two decision fixes)
packaged and its 15 -> 17 upgrade/rollback rehearsed on `feat/archive-handling`, which is
pushed to origin (the user authorized pushing work without institutional data). The intranet
runs pilot.15 as far as known; pilot.16 was never confirmed installed. This is a workspace
checkpoint, not evidence of a deployment.

## Start here

1. Read the root `AGENTS.md` completely.
2. Inspect `git status`, staged changes and the current diff. Preserve all work;
   do not reset, discard or automatically stage unrelated files.
3. Read `docs/architecture/FRONTEND_SEPARATION.md`, especially the complete UI
   inventory and the latest implementation/validation sections.
4. Read `docs/architecture/ENGINE_DEPLOYMENT_AND_WORKER_AGENT.md` and the remaining
   gates in `docs/security/HARDENING_PHASE_1.md`.
5. If continuing the client-flexibility or large-file work, read
   `docs/architecture/SERVICE_CLIENTS_AND_SCAN_PROFILES.md` (named profiles,
   client storage access, manifest intake and its console view) and
   `docs/architecture/MAPPED_SOURCE_INSPECTION.md` (steps 1-3 done; steps 4 and 5
   blocked on OPEN decisions).

## Git checkpoint

**Working branch: `feat/archive-handling`** (created 2026-10-05 from
`experiment/ui-redesign` at `04748b5`, so it carries the redesign too): the
per-client archive handling the user asked for ("users will send archives; MASP
must handle zips somehow"). See "Archives" in
`SERVICE_CLIENTS_AND_SCAN_PROFILES.md`. Same branch, also requested on
2026-10-05: the sign-in rail keeps only the product line (the user found the rest
"advert-like"), the expected 401 no longer shows as a red error on the sign-in
page, and a notification bell replaced the top bar health pill (recent detections
for everyone, failing health checks for admins, per-user read and clear markers; see
"Notification bell" in `FRONTEND_SEPARATION.md`). Packaged as pilot.14, deployed on
the intranet on 2026-10-06; its follow-up (the not-allowed outcome) is pilot.15,
packaged and rehearsed but not deployed. Merging it also brings the unmerged redesign along.

**Redesign branch: `experiment/ui-redesign`** (created 2026-10-02 from
`feat/frontend-separation-hardening` at `4b1a8da`; that branch has not moved, so
merging is a fast-forward). It holds the console redesign `4349311`, which the
user reviewed and approved on 2026-10-05 ("beğendim"), plus this handoff. It is
not merged into `feat/frontend-separation-hardening` yet: ask the user before
merging, and remember the deployed pilot.13 predates it. Going back to the old
look is `git switch feat/frontend-separation-hardening`.

Checkpoint branch: `feat/frontend-separation-hardening`, not merged to `main`.
`origin/feat/frontend-separation-hardening` was last confirmed at `94f01ed`;
**everything below is local and NOT pushed**. The user authorizes each push
explicitly because the repository is public. The PR to `main` has not been
opened (no `gh` on this host; the user opens it from the compare URL). Confirm
with `git log -1`, `git status` and a fresh `git fetch` before assuming anything
here is still current.

Commits after the last pushed `94f01ed`, oldest first:

- `54c6841` `deploy/pilot/rehearse_tls.sh`: disposable app + PostgreSQL + nginx
  (self-signed) rehearsal of the proxy trust settings; passed locally
- `a17a063` the pilot release bundle ships the console build inputs
  (`frontend/`); without them `install.sh` failed at the Dockerfile's first COPY
- `4ac88b0` `install.sh` refuses the example's placeholder
  `MASP_WORKER_ENROLLMENT_TOKEN` (public value: anyone could enroll a worker) and
  a non-Fernet `MASP_SECRET_ENCRYPTION_KEY`; both may be empty
- `82c696a` hash lookup redesign, technical About (release image, Python,
  database, per-engine versions, agent versions), theme-aware logo;
  `MASP_RELEASE` passed through the compose files
- `22161f5` release named `0.1.0-pilot.7`
- `31c1571` grouped navigation (Operations, Integrations, Infrastructure,
  Administration; phone menu), one UTC timestamp format, heartbeat wording,
  investigation links, copyable `X-Request-ID` on errors, collapsible help.
  Started by a second agent that ran out of credit; reviewed, four tests adapted
  to the intended behaviour, committed here
- `e6ecf41` operations visibility: health checks on System > Overview and in the
  top bar, ClamAV signature version/date in engine health, ICAP gateway activity
  record, System > ICAP and SIEM, intake retry/dismiss, client readiness per
  connection method, name search, ledger client picker, support bundle
- `2369905` notifications that nothing ever tried to deliver are "not in use",
  not critical (found on the live local stack)
- `7ca0274` handoff, AGENTS.md, architecture and deployment docs synced
- `748e829` Microsoft Defender marked `supported` (product-owner decision based
  on production use; label only). SCM-service run, failure/failover matrix and
  release signing stay open as hardening, not as done
- `ae1b0dc` ClamAV on networks without internet access: optional `clamav.env`
  beside the compose file (internal mirror, proxy, or `CLAMAV_NO_FRESHCLAMD`)
  and `deploy/pilot/load_clamav_signatures.sh` (sigtool-verified copy into the
  service volume; TCP `RELOAD` on a running clamd). Rehearsed in Docker's Linux VM
- `4bb4f57` release named `0.1.0-pilot.8`
- `69105bf` docs: the pinned ClamAV image ships an old database
- `2c2dd3b`, `1b24954`: handoff updates
- `2cbd4b0` storage protection architecture (`STORAGE_PROTECTION.md`)
- `44cbc8e` storage protection phase 1 core: protection worker, inventory,
  light tier, shared header classifier (`content_types.py`), storage outbox
- `365163d` browser API under `/api/ui/v1/storage` and a folder scanning
  health check
- `7eef7dd` an unreadable stored policy stops only its own location
- `5d8368b` Folder scanning console screens
- `f376270` `storage-protection` compose profile in all three compose files,
  env examples, README/deployment/architecture docs, handoff
- `366ca10` release named `0.1.0-pilot.9`; bundle and MASP image in `dist/`
  (PostgreSQL/ClamAV unchanged). The image passed a folder-scanning smoke run
  as UID 10001 with a read-only root, no capabilities and a root-owned 755/644
  share (3004 files crawled in 0.8 s, inspected in 9.8 s on a local volume).
  The operator's Turkish upgrade and test steps are `kilavuz/04-pilot9-klasor-tarama.md`
- `a710c0d` handoff for pilot.9
- `1dfb6f4`, `b86b617`, `437942a`: `deploy/pilot/offline_install.sh`, a
  one-command first installation for a host with no internet access; release
  named `0.1.0-pilot.10`. Rehearsed end to end on 2026-10-01 in an isolated Docker
  network (fresh server, allowed and unlisted ICAP clients): verify.sh passed, ICAP
  saw the client's real address, the DOCKER-USER rule dropped the unlisted host,
  and a rerun and an interrupted Docker install both recovered. The Docker offline
  archive became a flat apt repository carrying the full dependency closure
- `fce9fcb`, `3ef2fa2`, `0b83def`: Ubuntu 24.04 support (the intranet host runs
  24.04.5); `dist/` holds `jammy` and `noble` Docker/tools archives, rehearsed the
  same way on both releases
- `69f674e`, `3162c31`, `9c1a54e`: three installer fixes found on the first real
  intranet installation, none of which the container rehearsal could show: nginx's
  package postinst failed with IPv6 disabled (default site listens on `[::]:80`;
  now blocked through `policy-rc.d` and the default site removed), `/usr/local/bin`
  was absent, and a strict root umask left `tools/` unreadable by the containers
  (now `umask 022` plus `chmod go+rX tools`). apt's own error lines are shown on
  failure. The packaged pilot.10 ZIP predates these; the intranet host was fixed by
  hand
- `98b4091` ICAP samples are named from the encapsulated HTTP message
  (Content-Disposition, multipart part, or a URL segment with an extension) instead
  of always `icap_reqmod.bin`/`icap_respmod.bin`; the content type comes from the
  same message. Needed for the ledger and for the `file_type` extension check
- `4ca9392`, `e905d67`: handoff
- `e06779f` console times in the browser's time zone with an offset label, UTC on
  hover (`Timestamp`); Vitest/Playwright pin UTC
- `62a0f38` ICAP client binding shown on System > ICAP and SIEM, the client's
  Setup tab, health (unresolved key) and `verify.sh`
- `9c7082a` `deploy/pilot/upgrade.sh`, one-command offline upgrade
- `700f013` release named `0.1.0-pilot.11`
- `f26a72b`, `504b83f`: two defects found by the upgrade rehearsal (below):
  `verify.sh` read the PostgreSQL pool message instead of the binding, and a
  gateway rebound from `legacy-default` to its own client left a silent record
  that health reported as a stopped gateway (critical) for a week
- `ba7c944` handoff for pilot.11
- `3c44e55` per-client scan policy (see "Profile scan policy" in
  `SERVICE_CLIENTS_AND_SCAN_PROFILES.md`); `a8f60de` joins two violations as one
  sentence (seen in the rehearsal)
- `918ddfe` release named `0.1.0-pilot.12`
- `8e73dd3` handoff for pilot.12
- `33aae38` Office Open XML / OpenDocument files are not archives: intake made
  them batches and ICAP's `MASP_ICAP_BLOCK_ARCHIVES` blocked every docx/xlsx the
  engines had cleared (reported by the user from the intranet: "console allow,
  ICAP block"); the ICAP event now names the archive rule
- `e5a6ab8` release named `0.1.0-pilot.13`
- `67a11e5`, `4b1a8da`: handoff
- on `experiment/ui-redesign` only: `4349311` console redesign (see "Visual
  language" in `FRONTEND_SEPARATION.md`), then this commit: handoff

Pre-existing staged files to preserve: `bench_sample.txt`, `sample_30mb.bin`,
`sample_45mb.bin`, `sample_5mb.bin`, `skills-lock.json`. These are intentionally
excluded from every commit and remain staged locally; a plain `git commit -a` or
`git commit` without a pathspec would sweep them in, so every commit in this
branch's history was made with an explicit file list.

`docs/PILOT_FOLLOWUPS.md` must stay UNTRACKED: the repository is public and that
file still carries partner naming. Do not `git add` it.

## Current work

**2026-10-05 archive report follow-up (committed as `bf01efa`).** The archive-wide decision
now reaches the console report, exports, print view, public status/result and
browser contract previews, using the same bounded member reader as ICAP. Recorded
container risk and engine rows stay per-file. Running members keep result_ready
false (`/result` 409) and the console polling. Invalid policy or inconsistent
ownership/ancestry never falls back to container allow: reports suppress the
decision, previews fail, API returns 503 and ICAP blocks. Admission: 5000 members,
20000 results, 2 MiB routing/policy/name bytes, 64 KiB per engine policy, no member
raw output/findings. Added profile/archive policy values missing from the public
API schema. Packaged in pilot.14; release-container ICAP checks passed below.
Deployment,
capacity acceptance remains open (upgrade/rollback rehearsal passed, below).

**Verification recovered on 2026-10-06.** The interrupted session's final full
backend run finished on 2026-10-05: 1113 tests, OK, 179 environment/platform
skips. The initial run's API source-isolation test failure was fixed before
that final run; its standalone scan fixture now includes batch/role metadata.
The last edit added `engine_policy_review` to the public decision schema and
checks that a container requiring review is never promoted to archive allow.
After resuming, the archive, API authorization, public contract and browser
contract modules were rerun against the current tree: 65 tests, OK, 14
PostgreSQL-gated skips. Browser contracts and TypeScript typecheck also passed.
The prior session additionally passed 15 isolated PostgreSQL archive/notification
tests (including coherent report snapshots), all 200 frontend tests and the
production console build. Its disposable PostgreSQL container was stopped and
removed. No deployment was performed.

**Pilot.14 candidate, 2026-10-06.** Local commits `bf01efa` (archive policy and
notification markers) and `27fcc4f` (release version) are not pushed or merged.
The clean committed bundle built its Docker image successfully. Outputs under
`dist/`: `masp-pilot-0.1.0-pilot.14.zip` and
`masp-pilot-0.1.0-pilot.14-image.tar`, each with a SHA-256 sidecar.
ZIP SHA-256: `492c6155b61439ebf12e9a8d6b1cfcccba7f9211149ebb71062864ace676d29b`.
Image archive SHA-256: `8e923d9d233ad60eb78623cbbed0ef370a07d478a54da281d5c48d654e848545`.

All 39 Playwright workflows passed (exit 0). Windows fixture shutdown stalled;
the three identified test-owned server processes were stopped, allowing normal
report completion. An isolated native Compose project, `masp-archive14`, ran
all five services healthy from the exact release image. Eleven real ICAP cases
passed: inherited block, clean ZIP, password-encrypted ZIP, valid RAR, corrupt
ZIP, nested clean/encrypted ZIP, denied member type, 1001-member limit, nested
clean member scans and nested EICAR member scans. RAR is refused as unsupported;
this does not add RAR extraction. Console report and public status/result
contract previews matched profile decisions for every case. The inherited
gateway-wide archive block is separate from the clean per-scan report decision.
Evidence and test harnesses: ignored `dist/rehearsal-pilot14/`.
The disposable project containers, network and database/signature volumes were
removed after evidence was saved. The release image and artifacts remain.

**Upgrade/rollback rehearsal passed, 2026-10-06** (the user approved the Docker
socket mount for it). An `ubuntu:24.04` driver with the host socket and `/rehearse`
ran only compose project `masp-rehearse` (ports 18100/11344) with
`MASP_INSTALL_ROOT=/rehearse/opt`, `MASP_DATA_ROOT=/rehearse/srv`. Fresh pilot.13
install, a `fil` client bound to ICAP and traffic (13 verify passed); then
`upgrade.sh --dry-run` (only `MASP_IMAGE` and `./rules` moving to the data root),
`upgrade.sh` with the pilot.14 image removed from the host first so the tar load
ran: 9/9 steps, verify passed, every scan and `fil` kept, notification columns and
`idx_scan_jobs_detection_feed` added. ICAP after upgrade: clean ZIP still blocked
with inherited handling; with `fil` set to `inspect` clean ZIP allowed, encrypted
ZIP and EICAR blocked; the bell listed pre-upgrade detections. The printed
rollback restored pilot.13 (verify passed, columns gone, data as backed up), and
upgrading again after the rollback passed. Driver script and log:
`dist/rehearsal-upgrade14/`. Project, volumes, driver and `/rehearse` removed;
the live `masp` stack was untouched. Operator steps (Turkish):
`kilavuz/PILOT_14_DURUM.md`. Not deployed; no push or merge.

**Pilot.14 is deployed on the intranet (user, 2026-10-06).** First report from
it: a clean ZIP blocked over ICAP showed "malware detected" in the client product
while the ledger said No detection; `fil` was still on inherited archive handling,
so `MASP_ICAP_BLOCK_ARCHIVES` refused it. Fixed for pilot.15 in `78aa58a`
(favicon), `92e9046` (not allowed) and `d4ebac6` (release name), all tests passing
(backend 1123 SQLite; related modules plus `test_reliability_postgres` on
disposable PostgreSQL; frontend 201, e2e 39):
- ICAP block bodies name the kind of reason; "malware detected" only for a detection.
- **Not allowed** (see that section in `SERVICE_CLIENTS_AND_SCAN_PROFILES.md`),
  agreed with the user as one mechanism: every admission rule, the gateway archive
  rule included, is an intake violation; `profile_policy.NOT_ALLOWED` gives code,
  label and ICAP message; `scan_jobs.not_allowed` feeds a ledger badge/filter and
  the report. Not in the bell (user's choice); SIEM `policy.not_allowed` only when
  the new Scan policy setting is on. The gateway no longer applies its own rule.
- Adding a `scan_jobs` column flipped SQLite's index choice for the archive child
  presence probe (no statistics: a cost tie decided by row width); the probe now
  carries `nested.id > 0` so it always uses `idx_scan_jobs_parent`.
- Favicon and mobile theme colour now match the redesign's mark.
The five pre-existing staged files and the private untracked pilot follow-up
document remain untouched.

**Pilot.15 deployed by the user (2026-10-07), then the settings were reworked for pilot.16.**
The user found the settings screens hard to follow. Round one (`21d1207`, plain names,
controls and save flow) stays. Round two (`e3ffb2c`, a per-profile "what happens" table) was
rejected by the user as still confusing and replaced by **profile rules** (`6097eeb`, see
`docs/architecture/PROFILE_RULES.md`): an ordered list per profile, first match wins (size
range, type, disguised extension -> Scan with chosen engines, Light check, Allow without
scanning, Block), explicit last rule and explicit inconclusive choice, no inherited server or
gateway settings. Decisions made with the user: light check that finds nothing is allowed and
labelled; existing profiles convert automatically at startup; profiles decide everything
(`MASP_ICAP_BLOCK_ARCHIVES`/`_ON_REVIEW` only for `legacy-default`); "Allow without scanning"
exists; Block does not scan (a "scan, then block" option can come later if wanted); folder
scanning's archive default stays "hold for the full tier". `59a0d63` fixed the ICAP message for
a rule block (found in the rehearsal). Verification: backend 1147 SQLite OK, related modules
157 on disposable PostgreSQL OK, frontend 203, e2e 39/39, build and contracts clean.

**Pilot.17, 2026-10-08.** On top of pilot.16:
- Folder scanning follows profile rules (`de48245`); folders are added on the client's
  Storage tab. See "Folders follow profile rules" in `STORAGE_PROTECTION.md`.
- Exceptions (`17ad93e`, `5c4e89e`), requested by the user ("if an exception is added it
  suppresses every detection"): per-SHA-256, reason, client or global scope, expiry,
  revoke; frozen at intake; decision `exception_allow`; no bell or SIEM event. Added from
  System > Exceptions, a flagged ledger row or a blocked report. See "Exceptions" in
  `PROFILE_RULES.md`. Folder findings are not covered yet.
- A second agent's product security review (operator copy in `kilavuz/`, not tracked) found
  two bugs, both confirmed and fixed in `9f84110`: a light check whose Hash List failed was
  allowed as "light check only" (every check a rule names must now complete, otherwise the
  result is inconclusive), and ClamAV signature health showed only the newest report (every
  recent report of an enabled instance is now judged). Fixing it also exposed that the public
  `DecisionPolicy` list lacked every rule/exception policy, so the console's result-JSON
  preview failed for rule profiles; fixed in the same commit.
- The user agreed the review's order: decision correctness (done), then a small hardening
  round (login throttling, hashed dependency lock + SBOM, engine/signature version recorded
  per result, a public note that the risk score is not a probability), then archive-parser
  resource limits/isolation and per-client quotas; signed releases and MFA/SSO only if the
  institution asks.
Bundle from `a19985a`: `dist/masp-pilot-0.1.0-pilot.17.zip` SHA-256
`ac4e384f1fc7277f3c77cdf4ed3c349c2639a97af27471ce82ff5b4962c56b74`, image tar SHA-256
`c743aeb5159912e92970d1135451f2ccf2504a3ad7b9efdda7d5715387d1b012`. Rehearsal
(`dist/rehearsal-upgrade17/`, log beside it) from a fresh pilot.15 with `fil`: dry run changed
only `MASP_IMAGE` (plus the fresh install's rules directory); upgrade 9/9; `fil` converted as in
pilot.16; sample rules gave the pilot.16 outcomes; an exception for EICAR on `fil` let it
through with `exception_allow`, the ClamAV detection kept, no bell entry, no outbox row;
rollback to 15 passed; re-upgrade passed; teardown left nothing. Verification: backend 1174
SQLite OK, 329 related tests on disposable PostgreSQL OK, frontend 214, e2e 40/40 (ledger
exception flow covered by unit tests only), build and contracts clean. Operator steps:
`kilavuz/PILOT_17_DURUM.md`.

**Pilot.16 packaged and rehearsed, 2026-10-07.** Bundle from `59a0d63`;
`dist/masp-pilot-0.1.0-pilot.16.zip` SHA-256
`41396d406c924f1f9498c42c9067b46ad619af36815809c3a2610f3749055d3c`,
`dist/masp-pilot-0.1.0-pilot.16-image.tar` SHA-256
`d84c79b856d8c4ac45ee3a14fce8223a7537be96c4da082f00b58dd786f720a3`. Same driver method
(`dist/rehearsal-upgrade16/rehearse.sh`, log beside it). Fresh pilot.15 with `fil` (empty
policy, ICAP-bound): zips refused as before. Dry run changed only `MASP_IMAGE` (plus the fresh
install's `./rules` move); upgrade 9/9 with the image removed from the host first. `fil` was
converted to "archive -> Block; every other file -> Scan (Static Metadata, ClamAV, YARA)",
inconclusive Block, because the pilot compose sets `MASP_ICAP_BLOCK_ON_REVIEW=1`;
`legacy-default` kept `{}`. ICAP after conversion: same outcomes, block body "files like this
are not accepted". After an admin rule set (large -> Light check File Type + Hash List,
archive -> Scan + open and check, else Scan): clean zip allowed, encrypted zip blocked as
`archive_encrypted`, a 2 MiB file got only the two light engines and "Allow (light check
only)", EICAR blocked. Rollback restored pilot.15 (verify passed, `fil` back to `{}`), and
upgrading again passed. Project, volumes, driver and `/rehearse` removed; live `masp`
untouched. Operator steps (Turkish): `kilavuz/PILOT_16_DURUM.md`. Not deployed; no push or merge.

**`1fdf768` Hash List engine.** Decisions made with the user: one global list
(not per engine instance), and an allowlist match is informational only — it
never suppresses another engine or produces an allow decision. The adapter
compares the MASP-computed SHA-256 (never a client value), reads no sample bytes,
is `detection=False` so "not listed" is never coverage, and reports a failed
lookup as `failed`. It reads MASP's database while scanning, so it carries a new
`requires_database` capability: control-API workers neither advertise nor run
it. Two pre-existing `file_type` gaps were found and fixed in the same commit: it
had no Engines-page setup branch (creation always failed) and no default worker
key list included it. Existing deployments with an explicit
`MASP_WORKER_ENGINE_KEYS` in their `.env` must add `file_type,hash_list`
themselves; an admin must also create the Hash List engine and assign it to
profiles — nothing is seeded.

**`ce94ace` deferred intake visibility.** Closes the gate the manifest intake
commit left open. The manifest worker now records each cycle and the
configuration it ran with in the `manifest_intake_last_cycle` setting, because
the API process does not share the worker's environment. Error text for
rejections and cycles is stored and displayed with absolute paths replaced by
`<path>`; OSError messages previously carried the share path into storage. The
view is read-only: nothing is cleared, retried or dismissed from the console.

**`720da8e`: deferred retry no longer depends on live configuration.** A repeat
`client_request_id` is answered from the accepted record before resolving any
live routing, comparing only what the client asserted: backend key, object id,
expected size, expected SHA-256, archive mode and `requested_profile_id` (NULL
means "use the default"). Descriptive metadata is first-write-wins. A genuinely
different request for an existing id is still a `409`, and the frozen snapshot
stays authoritative. Before this, renaming a profile, engine or client turned a
byte-identical retry into a permanent `409`. Full contract in
`SERVICE_CLIENTS_AND_SCAN_PROFILES.md` under "Retrying a deferred submission".

**`98128da` legacy UI retirement.** The console is the only browser UI and is
served by the application image (`d7ad4b2`), so pilot/production need no extra
container. Former GET paths redirect (`/scans/{id}` resolves manual vs automation
only for a signed-in operator). `MASP_SHOW_DEV_LOGIN_HINTS` was removed.

**`73f3264` scan outcomes.** Raised by the user: a scan whose engines all failed
showed "completed" with zero risk, and clean scans showed an orange "low 10".
Scoring added 10 points for a clean result; decisions never depended on it.
Integrators see both changes through the API.

**`93e77ca` deployment fixes.** Found in a go-live review cross-checked with a
second agent: the manifest service was missing from prod/pilot compose; the
pilot backup/restore scripts stopped only `app worker icap`, leaving intake and
notification workers writing during a dump/restore (a fake-docker test now
drives both scripts); and Uvicorn trusted `X-Forwarded-Proto` only from
127.0.0.1, so behind a TLS proxy every console save would fail the same-origin
check and remote workers would be refused. `rehearse_tls.sh` (`54c6841`)
proves the MASP side against a self-signed nginx; a real institutional proxy
has still not been exercised.

**Offline upgrade path (rehearsed 2026-09-25).** The pilot server has no
internet except ClamAV updates, so releases travel as the bundle ZIP plus one
`docker save` of `masp-pilot:<version>` (PostgreSQL and ClamAV digests are
unchanged since pilot.2, and project and volume names never changed). The
upgrade was replayed inside Docker's Linux VM with the real release scripts
from pilot.2 and from pilot.5: old install and verify, old backup, carried env
(`awk` appends keys missing from the new example), new `install.sh --no-build`,
new verify, then rollback (old release on the migrated database, old restore).
All passed. Two findings are written into the operator manual: upgrading from a
root-container release (pilot.2) without `install.sh` leaves storage root-owned
and every upload fails with 500; `restore.sh` restarts services without waiting
for health, so verify after the app is healthy.

**Operations visibility (`e6ecf41`, `2369905`).** The health report
(`app/services/health_read.py`, `GET /api/ui/v1/system/health`) evaluates
workers, queue age (with why scans wait), engines (using the Engines screen's
own verdicts), ClamAV signature age, sample storage, manifest and deferred
intake, the ICAP gateway and SIEM notifications. On the live local stack it
immediately surfaced a real problem: ClamAV had not updated for three days
(Docker paused while the host slept). The ICAP gateway now writes
`icap_gateway_status:<client key>:<port>` every 30 seconds; older gateways do
not report, so an upgraded server shows ICAP as "not in use" until the icap
container runs this release.

**Intranet host (state reported by the user, 2026-10-02 end of day).** A fully
offline installation on Ubuntu 24.04.5 (hardened: IPv6 off, strict root umask, no
`/usr/local/bin`, SSH port forwarding disabled). Never name the host, the
institution or its addresses in tracked files; the operator guide and carry
folders live in git-ignored `kilavuz/` and `dist/`.

- Installed 2026-10-01 from pilot.10 with `offline_install.sh` plus three manual
  fixes that later became `69f674e`, `3162c31`, `9c1a54e`.
- **Upgraded by the user to `0.1.0-pilot.13` with `upgrade.sh`; reported as
  working.** The first integration is a RESPMOD-only ICAP product bound to the
  service client `fil` (`MASP_ICAP_SERVICE_CLIENT_KEY=fil`, set by the user).
- What the user hit on the way, all fixed in pilot.13: scans filed under
  `legacy-default` (the binding is now visible in the console and `verify.sh`);
  ICAP samples named `icap_respmod.bin` (names now come from the encapsulated HTTP
  message, but a product that sends no Content-Disposition and no file-like URL
  still yields that name; a header-logging diagnostic was offered, not built);
  clean docx/xlsx blocked while the ledger said allow (Office files were treated
  as archives and hit `MASP_ICAP_BLOCK_ARCHIVES`).
- The scan policy of `fil` may have been set by the user in the console; what
  they chose is not known.
- The console was reachable only through an SSH tunnel until the network team
  opens 443 (DNS A record, firewall, certificate from the internal CA for the CSR
  at `/etc/ssl/masp/masp.csr`; steps were given in Turkish). If the user prepended
  `DisableForwarding no`, `AllowTcpForwarding local`, `PermitOpen 127.0.0.1:443`
  to `/etc/ssh/sshd_config`, revert it from `/root/sshd_config.masp-yedek` once
  443 is open.

**Releases in `dist/` (git-ignored), each a bundle zip plus the MASP image alone,
both with `.sha256`; PostgreSQL and ClamAV images unchanged since pilot.2:**

- `0.1.0-pilot.17` (commit `a19985a`): pilot.16 plus folder rules, exceptions and the
  light-check/signature-health fixes. Rehearsed 15 -> 17 (conversion, rules, exception,
  rollback, re-upgrade), passed.
- `0.1.0-pilot.16` (commit `59a0d63`): profile rules, plain settings screens. Rehearsed
  15 -> 16 (conversion, rules, rollback, re-upgrade), passed.
- `0.1.0-pilot.15` (commit `d4ebac6`, deployed on the intranet 2026-10-07): pilot.14 plus the not-allowed outcome and
  ICAP block bodies that name the reason. Rehearsed 14 -> 15, rollback passed.
- `0.1.0-pilot.14` (commit `27fcc4f`, deployed on the intranet 2026-10-06): archive
  handling, notification bell. Rehearsed 13 -> 14, rollback passed.
- `0.1.0-pilot.13` (commit `e5a6ab8`): pilot.12 plus
  the Office fix. Rehearsed 12 -> 13: docx/xlsx blocked on 12 (reproduced) and
  allowed on 13, a plain zip still blocked, rollback passed.
- `0.1.0-pilot.12` (commit `a8f60de`): pilot.11 plus per-client scan policy.
  Rehearsed 11 -> 12 with a `fil` policy over ICAP (text allowed; an exe named
  `invoice.pdf` and a `.ps1` rejected without a scan, counted as
  `policy_rejected`; EICAR blocked), rollback passed.
- `0.1.0-pilot.11` (commit `504b83f`): installer fixes, ICAP file names, ICAP
  client binding, `upgrade.sh`, local time. Rehearsed 10 -> 11, rollback passed.
- Never rehearsed: `upgrade.sh` from a release older than pilot.10. The other
  pilot server is on pilot.6 or pilot.7; run `--dry-run` there first.

**Decisions and offers waiting on the user:**

- **Console redesign:** approved; merge `experiment/ui-redesign` into
  `feat/frontend-separation-hardening` (fast-forward) and ship it in the next
  pilot release, or keep iterating first. Offered second pass: dashboard table
  density, scan report, engine cards, phone layout.

- **Archives over ICAP: packaged in pilot.14, not deployed.** The
  user chose (2026-10-05) a per-profile `archive_handling`: `inspect` as the
  recommended default (engines scan the archive whole; MASP opens it at intake
  and blocks encrypted, damaged, over-limit, unopenable formats such as RAR, and
  members the content rule refuses or the hash blocklist lists) and
  `scan_members` as the stronger option (every member also scanned; ICAP waits for
  all of them). Decisions taken with the recommended answers: encrypted blocks,
  unopenable formats block, member content follows the profile's content rule.
  Open follow-ups: RAR extraction support (needs a decision on an unrar/7z
  binary and its licence) and per-member SHA-256 deduplication for `scan_members`
  capacity. Release-container ZIP/encrypted ZIP/RAR checks passed on 2026-10-06.
  Before deployment, complete the upgrade/rollback rehearsal and explicitly set
  the intended client profile in the console.
- **Analytics tab** with charts: requested, then deferred by the user ("not needed
  now"). Proposed scope: scans over time by source and client, decisions,
  detecting engines, blocked types and policy rejections, ICAP wait times and
  timeouts.
- **ICAP header diagnostic** (log encapsulated header names and the URL, never
  content) if RESPMOD names stay `icap_respmod.bin`.
- **Institution branding**: generic mechanism only (deployment-provided logo and
  product name under `/srv/masp/branding/`); waiting for logo format and name.
- Smaller: keep non-ASCII display names (storage names are ASCII-only); a RESPMOD
  option for `tools/icap_probe.py`.

**Pilot server:** the pilot.9 upgrade was paused by the user at the `.env.pilot`
step (nothing was installed). `upgrade.sh` from pilot.13 is the way to resume,
starting with `--dry-run`.

**Next steps agreed with the user, in order:**

1. Push the commits above and open the PR to `main` -- **only with the user's
   explicit approval** (the repository is public; commit messages were checked
   for institution and host names).
2. On the pilot server (operator-run; the agent has no access): real network
   share manifest test once the firewall allows the pilot host -> file server TCP 445
   (one direction only), a backup/restore rehearsal on the real host, a
   capacity run with realistic file sizes (the local worker was once killed
   with exit 137 under load).
3. Low priority, separate change: remove database helpers that lost their only
   callers with the legacy UI (`list_users`, `update_service_client`,
   `revoke_api_client_credential`, `list_engine_results_by_scan_ids`, ...).

**Open threads with the user (2026-09-29):**

- Trellix and ESET adapters are next, after the intranet install. Blocked on the
  user naming the exact products and licenses the institution has (ESET Server
  Security, ESET PROTECT, Trellix Endpoint Security, Trellix ATD, an ICAP-capable
  gateway) and on test access. Suggested first: a generic ICAP-client adapter,
  validated locally against c-icap + ClamAV, then one response profile per
  vendor. Never write an adapter without real product responses.
- Offered, not started: an offline Windows worker kit (Python installer, wheels
  including pywin32, the agent bundle) and a Turkish manual for a remote
  Defender worker on the intranet. A remote worker needs HTTPS on MASP and
  `MASP_WORKER_ENROLLMENT_TOKEN` set only while enrolling.
- The user asked for server sizing; the answer (not in the repo): 8 vCPU / 16 GB
  for the pilot, ClamAV ~1 GB idle and about double during a reload, disk sized
  as daily files x average size x retention days plus about 20 GB, backups on a
  separate target. No realistic capacity run has been done yet.
- Research ideas discussed, none started: retrohunt (rescan stored samples on
  new signatures and notify SIEM), document analysis and CDR, an engine efficacy
  lab, signed offline update bundles.

**Storage protection (2026-09-29).** Folder-watch intake without manifests is
no longer parked: the user chose a broader "storage protection" feature, agreed in
`docs/architecture/STORAGE_PROTECTION.md`. **Phase 1 is implemented** (crawl mode,
inventory, light tier, findings and SIEM events, browser API, Folder Scanning
screens, health check, `--profile storage`); read "Phase 1 as built" there for the
deliberate differences. Not yet exercised: a real SMB share, a real SIEM receiving
`storage.finding` events, and any capacity run. Phase 2 (full tier: verified
in-place reads, content deduplication, evidence copies) is next, on the user's
go-ahead. The storage team will integrate to MASP's choice, so for their uploads
the deferred API is the recommended path and the manifest the fallback.

The intranet server request was drafted with the user: Ubuntu Server 22.04 x86_64
(the offline kits in `dist/` are `jammy-amd64`), 8 vCPU / 16 GB, 80 GB OS plus a
200 GB data disk at `/srv/masp`, TLS from the internal CA (required because the
Defender worker only talks HTTPS), plus a Windows Server 2022 Defender worker
(4 vCPU / 8 GB / 80 GB, Defender active, cloud sample submission off, signatures
from an internal source, outbound 443 to MASP only). Still to prepare: an offline
Windows worker kit (Python installer and wheels including pywin32) and a Turkish
worker manual in `kilavuz/`.

**Parked for user decisions:** `MAPPED_SOURCE_INSPECTION.md` steps 4
(explicit narrow coverage) and 5 (in-place reading); a "Page N" indicator for
the API ledger; wiring Hash List into the API hash lookup.

**Pilot server state (reported by the user, 2026-09-28).** An Ubuntu pilot
host, offline except ClamAV updates, reached through a PAM client. It was
upgraded from pilot.5 to pilot.6 in place (old install lives in `/opt/masp`, the
new release in `/opt/masp/masp-pilot-0.1.0-pilot.6`, `/opt/masp/current` links
to it, `/usr/local/bin/masp` wraps compose). The app binds `127.0.0.1:8000`
without a proxy (`MASP_SESSION_SECURE` empty). A pilot.7 package was handed over;
whether it is installed is not known. The manifest test against a real share
is blocked: the pilot host can ping the file server but TCP 445 times out
(`mount error(115)`), which needs a firewall rule. `cifs-utils` presence on the
server is unconfirmed. Operator manuals in Turkish live in `kilavuz/`
(`01-kurulum.md`, `02-offline-yukseltme.md`), excluded from git through
`.git/info/exclude` at the user's request.

**Local environment notes:** the live local stack was rebuilt from `2369905` on
2026-09-28 (volumes kept) and now also runs the `icap` profile on
`127.0.0.1:1344`. `.env` has `MASP_MANIFEST_CLIENT_KEY=drive` (the
client created in the console is `drive`, id 238, granted `drive`/`uploads/`).
Test drops live in `deferred-source/uploads/2026/09/24/` (git-ignored);
`test-2.json` is a deliberately malformed manifest whose rejection count was
inflated by the spin bug before `8d6c042`. `requirements.txt` shows as modified
only because of line endings; its content is unchanged.

**Deployment gates outstanding:** capacity measurement against realistic
Drive-sized files (tooling exists in `tools/benchmark_*.py`), a real
institutional TLS proxy, production-scale PostgreSQL load, real-client ICAP
framing confirmation, and per-client rate limiting.

## Verification and environment safety

- Full backend: `python -m unittest discover -s tests`. Last full run (2026-10-02,
  tree of `33aae38`, SQLite): **1065 tests, OK, 149 skipped** (the skips are the
  PostgreSQL-gated modules). The policy, profile, operations-health and deferred
  concurrency modules then passed against a disposable PostgreSQL 16 (89 tests,
  none skipped). The pilot script tests need Git Bash on Windows and are skipped
  where no POSIX bash exists; they drive the pilot scripts with a fake docker.
- PostgreSQL tests require `MASP_TEST_POSTGRES_URL` pointing only at a disposable
  database: tests drop/recreate its public schema. Never use the live MASP DB.
  Disposable containers used on this branch (ports 15441-15444, names
  `masp-test-pg-*`) were started with `--rm` and stopped; none should remain
  (`docker ps -a` to check).
- Console preview without real data: from `frontend/`, run
  `python ../tools/serve_console_fixture.py` (port 18765) and
  `MASP_BACKEND_URL=http://127.0.0.1:18765 npx vite --host 127.0.0.1 --port 5175`,
  then sign in at `http://127.0.0.1:5175/console/` as `console-admin` /
  `console-test-only`. Stop both before `run test:e2e`, which starts its own on
  the same ports.
- Frontend: `npm --prefix frontend test` (192 tests passing on both branches;
  e2e 39/39 on `experiment/ui-redesign` on 2026-10-02), `run build`,
  `run contracts:check`. Regenerate contracts with
  `npm --prefix frontend run contracts:generate` after browser API changes.
  `run test:e2e` for Playwright (39 workflows, all passing on 2026-10-02).
- Release rehearsal (how pilot.11 to 13 were proven; repeat it for every release
  that changes deploy scripts or ICAP): package with
  `tools/package_pilot_release.py` (it refuses uncommitted inputs), build the
  image from the extracted bundle, `docker save` it and write the `.sha256` as
  `<hash>  <name>`. Run an `ubuntu:24.04` container with `/var/run/docker.sock`
  and `-v /rehearse:/rehearse` (the same path the daemon sees, so compose bind
  mounts resolve) plus the `docker` CLI and compose plugin copied from
  `docker:cli`; install the old release there under project `masp-rehearse`
  with ports 18100/11344, then `upgrade.sh --dry-run`, `upgrade.sh`, ICAP probes,
  the printed rollback, and finally `down -v` and removal of `/rehearse`. This
  found three defects the fake-docker tests missed (the PostgreSQL pool message
  in `verify.sh`, the rebound-gateway false critical, Office files as archives).
  In Git Bash set `MSYS_NO_PATHCONV=1` for docker paths.
- Browser acceptance uses temporary SQLite and a fixture server, not live data.
  On Windows Playwright teardown may leave fixture processes running; identify
  the exact owned PIDs before stopping them (none were left this session).
- Preserve live containers `masp-app-1`, `masp-worker-1`, `masp-icap-1`,
  `masp-postgres-1`, `masp-clamav-1`, `masp-deferred-intake-1`,
  `masp-manifest-intake-1` and `masp-storage-protection-1` (project `masp`).
  They were rebuilt from `2369905` on 2026-09-28; volumes were kept.
  Run heavy suites sequentially: running the full suite,
  e2e and a disposable PostgreSQL concurrently previously pushed the live
  containers into exit 137. Never retain real credentials in this handoff or
  test artifacts.

## Open acceptance gates

Production-shaped PostgreSQL load, a real institutional TLS proxy,
large/oversized output handling, per-client rate limiting, and
installed Windows SCM/failure/failover/signing acceptance remain open. Local
tests do not promote production engine support. See "Deployment gates
outstanding" above for what was actually discussed with the user and why each
one is still open.
