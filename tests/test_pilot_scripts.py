"""Behaviour of the pilot backup/restore scripts against a recording fake docker."""
import os
import shutil
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
BASH = shutil.which("bash")

# Runs backup.sh, then restore.sh from the backup it produced, with a fake
# `docker` that reports a running project and records every call it receives.
HARNESS = r'''
set -euo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/storage" "$work/rules" "$work/out"
echo sample > "$work/storage/sample.bin"
echo 'rule r { condition: false }' > "$work/rules/r.yar"
export FAKE_DOCKER_LOG="$work/docker.log"
cat > "$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$1" in
  ps) printf '%s\n' "c-app app" "c-worker worker" "c-pg postgres" "c-clam clamav" \
        "c-def deferred-intake" "c-man manifest-intake" "c-note notification" ;;
  compose) if [[ "$*" == *pg_dump* ]]; then echo FAKE-DUMP; fi; cat > /dev/null || true ;;
esac
FAKE
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH"
printf 'MASP_STORAGE_DIR=%s\nMASP_RULES_DIR=%s\n' "$work/storage" "$work/rules" > "$work/env"
bash "$ROOT/deploy/pilot/backup.sh" --env-file "$work/env" --output-dir "$work/out" > /dev/null
echo '--- restore' >> "$FAKE_DOCKER_LOG"
bash "$ROOT/deploy/pilot/restore.sh" --env-file "$work/env" --backup-dir "$(ls -d "$work"/out/masp-pilot-*)" --yes > /dev/null 2>&1
cat "$FAKE_DOCKER_LOG"
'''

WRITERS = "c-app c-worker c-def c-man c-note"


# On Windows only Git Bash qualifies; System32 bash.exe is WSL with its own filesystem.
POSIX_BASH = BASH is not None and (sys.platform != "win32" or "Git" in BASH)


@unittest.skipUnless(POSIX_BASH, "requires a POSIX bash (Git Bash on Windows)")
class PilotBackupScopeTests(unittest.TestCase):
    def run_harness(self) -> tuple[list[str], list[str]]:
        result = subprocess.run([BASH, "-c", HARNESS], capture_output=True, text=True,
                                env={"ROOT": ROOT.as_posix(), "PATH": os.environ["PATH"]},
                                timeout=120)
        self.assertEqual(result.returncode, 0, result.stderr)
        backup, restore = result.stdout.split("--- restore")
        return backup.strip().splitlines(), restore.strip().splitlines()

    def assert_writers_paused_around(self, calls: list[str], data_step: str) -> None:
        stops = [call for call in calls if call.startswith("stop ")]
        starts = [call for call in calls if call.startswith("start ")]
        # Every running writer is stopped, including intake and notification
        # workers started under profiles; PostgreSQL and ClamAV keep running.
        self.assertEqual(stops, [f"stop {WRITERS}"])
        self.assertEqual(starts, [f"start {WRITERS}"])
        step = next(index for index, call in enumerate(calls) if data_step in call)
        self.assertLess(calls.index(stops[0]), step)
        self.assertGreater(calls.index(starts[0]), step)

    def test_backup_and_restore_pause_every_running_writer(self) -> None:
        backup, restore = self.run_harness()
        self.assert_writers_paused_around(backup, "pg_dump")
        self.assert_writers_paused_around(restore, "pg_restore")

    def test_nothing_that_was_not_running_is_started(self) -> None:
        # The old scripts ran `compose start app worker icap` unconditionally.
        backup, restore = self.run_harness()
        self.assertFalse(any(" start " in f" {call} " and "compose" in call for call in backup + restore))


# Runs install.sh --dry-run on a fake Linux host with a fake docker; prints its
# stderr. $1 and $2 are the enrollment token and secret key to validate.
INSTALL_HARNESS = r'''
set -uo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/storage" "$work/rules"
printf '#!/usr/bin/env bash
echo Linux
' > "$work/bin/uname"
printf '#!/usr/bin/env bash
exit 0
' > "$work/bin/docker"
chmod +x "$work/bin/uname" "$work/bin/docker"
export PATH="$work/bin:$PATH"
cat > "$work/env" <<ENV
MASP_POSTGRES_PASSWORD=$(printf 'p%.0s' {1..32})
MASP_API_TOKEN=$(printf 'a%.0s' {1..32})
MASP_ADMIN_PASSWORD=admin-password-long
MASP_ICAP_BIND=127.0.0.1:1344
MASP_ICAP_ALLOWED_IPS=127.0.0.1
MASP_STORAGE_DIR=$work/storage
MASP_RULES_DIR=$work/rules
MASP_WORKER_ENROLLMENT_TOKEN=$1
MASP_SECRET_ENCRYPTION_KEY=$2
ENV
bash "$ROOT/deploy/pilot/install.sh" --env-file "$work/env" --dry-run 2>&1 >/dev/null
'''


@unittest.skipUnless(POSIX_BASH, "requires a POSIX bash (Git Bash on Windows)")
class PilotInstallSecretTests(unittest.TestCase):
    def install_errors(self, enrollment_token: str, secret_key: str) -> str:
        result = subprocess.run([BASH, "-c", INSTALL_HARNESS, "harness", enrollment_token, secret_key],
                                capture_output=True, text=True,
                                env={"ROOT": ROOT.as_posix(), "PATH": os.environ["PATH"]},
                                timeout=60)
        return result.stdout

    def test_placeholder_enrollment_token_is_refused(self) -> None:
        # The example's placeholder is public; accepting it lets anyone enroll a worker.
        errors = self.install_errors("CHANGE_ME_LONG_RANDOM_WORKER_ENROLLMENT_TOKEN", "")
        self.assertIn("replace MASP_WORKER_ENROLLMENT_TOKEN", errors)
        self.assertIn("at least 32", self.install_errors("short-token", ""))

    def test_placeholder_secret_key_is_refused(self) -> None:
        errors = self.install_errors("", "CHANGE_ME_FERNET_KEY")
        self.assertIn("MASP_SECRET_ENCRYPTION_KEY must be a Fernet key", errors)

    def test_real_or_empty_values_pass_the_secret_checks(self) -> None:
        for token, key in (("", ""), ("t" * 40, "A" * 43 + "=")):
            errors = self.install_errors(token, key)
            self.assertNotIn("MASP_WORKER_ENROLLMENT_TOKEN", errors)
            self.assertNotIn("MASP_SECRET_ENCRYPTION_KEY", errors)


# Runs load_clamav_signatures.sh with a fake docker that records its calls.
# $1: "full" (all three databases) or "partial"; $2: "running" or "stopped".
SIGNATURE_HARNESS = r"""
set -uo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin" "$work/sigs"
export FAKE_DOCKER_LOG="$work/docker.log" FAKE_RUNNING="$2"
cat > "$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$*" == *" ps -q clamav"* ]]; then [[ "$FAKE_RUNNING" == running ]] && echo c-clam; exit 0; fi
if [[ "$*" == *zPING* ]]; then printf 'PONG'; exit 0; fi
if [[ "$*" == *zRELOAD* ]]; then printf 'RELOADING'; exit 0; fi
exit 0
FAKE
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH"
touch "$work/sigs/main.cvd" "$work/sigs/bytecode.cvd"
[[ "$1" == full ]] && touch "$work/sigs/daily.cld"
printf 'MASP_STORAGE_DIR=/tmp\n' > "$work/env"
bash "$ROOT/deploy/pilot/load_clamav_signatures.sh" --env-file "$work/env" "$work/sigs" 2>&1
echo "exit=$?"
echo '--- docker'
cat "$FAKE_DOCKER_LOG" 2>/dev/null
"""


@unittest.skipUnless(POSIX_BASH, "requires a POSIX bash (Git Bash on Windows)")
class PilotSignatureLoaderTests(unittest.TestCase):
    def run_loader(self, databases: str, state: str) -> tuple[str, list[str]]:
        result = subprocess.run([BASH, "-c", SIGNATURE_HARNESS, "harness", databases, state],
                                capture_output=True, text=True,
                                env={"ROOT": ROOT.as_posix(), "PATH": os.environ["PATH"]}, timeout=60)
        output, _, calls = result.stdout.partition("--- docker")
        return output, calls.strip().splitlines()

    def test_an_incomplete_set_is_refused_before_docker_is_touched(self):
        output, calls = self.run_loader("partial", "stopped")
        self.assertIn("missing daily.cvd or daily.cld", output)
        self.assertIn("exit=1", output)
        self.assertEqual(calls, [])

    def test_databases_go_through_the_clamav_service_and_a_running_clamd_reloads(self):
        output, calls = self.run_loader("full", "stopped")
        self.assertIn("exit=0", output)
        copy = next(call for call in calls if " run " in f" {call} ")
        # The service's own image and volume, never the network or a host path guess.
        self.assertIn("run --rm --no-deps -T --entrypoint sh", copy)
        self.assertTrue(copy.split(" clamav -c ")[0].endswith(":/incoming:ro"), copy)
        self.assertFalse(any("zRELOAD" in call for call in calls))
        self.assertIn("clamd loads them when the stack starts", output)
        output, calls = self.run_loader("full", "running")
        self.assertIn("clamd is reloading the signatures.", output)
        self.assertTrue(any("zRELOAD" in call for call in calls))


if __name__ == "__main__":
    unittest.main()


# Runs verify.sh with a fake docker; the icap container's binding lookup prints $1.
VERIFY_HARNESS = r"""
set -uo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
mkdir -p "$work/bin"
export FAKE_BINDING="$1" FAKE_DOCKER_LOG="$work/docker.log"
cat > "$work/bin/docker" <<'FAKE'
#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
if [[ "$*" == *"exec -T icap python -c"* ]]; then
  # Like the real container with PostgreSQL: importing the app prints first.
  printf 'MASP DB pool enabled (min=0, max=4)\r\nMASP_ICAP_BINDING|%s\r\n' "$FAKE_BINDING"
fi
exit 0
FAKE
chmod +x "$work/bin/docker"
export PATH="$work/bin:$PATH"
touch "$work/env"
bash "$ROOT/deploy/pilot/verify.sh" --env-file "$work/env" 2>&1
echo "EXIT=$?"
grep -c icap_probe "$FAKE_DOCKER_LOG"
"""


@unittest.skipUnless(POSIX_BASH, "requires a POSIX bash (Git Bash on Windows)")
class PilotVerifyBindingTests(unittest.TestCase):
    def verify(self, binding: str) -> tuple[str, int, int]:
        result = subprocess.run([BASH, "-c", VERIFY_HARNESS, "harness", binding], capture_output=True, text=True,
                                env={"ROOT": ROOT.as_posix(), "PATH": os.environ["PATH"]}, timeout=60)
        output, exit_line, probes = result.stdout.rsplit("\n", 3)[0], *result.stdout.strip().splitlines()[-2:]
        return output, int(exit_line.removeprefix("EXIT=")), int(probes)

    def test_a_bound_client_is_named_and_the_probes_run(self) -> None:
        output, code, probes = self.verify("client|fil||File gateway | east")
        self.assertEqual((code, probes), (0, 3))
        self.assertIn("filed under service client File gateway | east (fil).", output)

    def test_the_compatibility_client_is_a_warning_not_a_failure(self) -> None:
        output, code, probes = self.verify("legacy_default|legacy-default|Scans are filed under the compatibility client.|Legacy API / ICAP")
        self.assertEqual((code, probes), (0, 3))
        self.assertIn("WARNING: ICAP scans are filed under the compatibility client", output)

    def test_an_unresolved_key_stops_before_the_probes_with_the_reason(self) -> None:
        # No display name: an empty field must not shift the reason into another one.
        output, code, probes = self.verify("unresolved|typo|No service client has the key typo.|")
        self.assertEqual((code, probes), (1, 0))
        self.assertIn("ICAP client key 'typo' does not resolve: No service client has the key typo.", output)


# Runs upgrade.sh from a scratch copy of the new bundle against a fake old
# release and a fake docker. $1: extra upgrade.sh arguments; $2: binding line the
# new verify.sh reads; $3: "images missing" to leave PostgreSQL's image unloaded;
# $4: "rules taken" to pre-fill the data rules directory.
UPGRADE_HARNESS = r"""
set -uo pipefail
work="$(mktemp -d)"
trap 'rm -rf "$work"' EXIT
new="$work/opt/masp-pilot-0.1.0-pilot.11"
old="$work/opt/masp-pilot-0.1.0-pilot.6"
mkdir -p "$work/bin" "$new/deploy/pilot" "$new/tools" "$old/deploy/pilot" "$old/rules" "$work/srv/storage" "$work/srv/backups"
cp "$ROOT"/deploy/pilot/*.sh "$new/deploy/pilot/"
cp "$ROOT/docker-compose.pilot.yml" "$ROOT/.env.pilot.example" "$new/"
printf '{"version": "0.1.0-pilot.11"}\n' > "$new/RELEASE.json"
printf '{"version": "0.1.0-pilot.6"}\n' > "$old/RELEASE.json"
echo 'rule custom { condition: false }' > "$old/rules/custom.yar"
password="$(printf 'p%.0s' {1..32})"
token="OLD-SECRET-API-TOKEN-$(printf 'a%.0s' {1..32})"
{
  echo "MASP_IMAGE=masp-pilot:0.1.0-pilot.6"
  echo "MASP_POSTGRES_IMAGE=postgres:16-alpine"
  echo "MASP_POSTGRES_PASSWORD=$password"
  echo "MASP_API_TOKEN=$token"
  echo "MASP_ADMIN_PASSWORD=old-admin-password-long"
  echo "MASP_ICAP_BIND=127.0.0.1:1344"
  echo "MASP_ICAP_ALLOWED_IPS=127.0.0.1"
  echo "MASP_ICAP_SERVICE_CLIENT_KEY=fil"
  echo "MASP_STORAGE_DIR=$work/srv/storage"
  echo "MASP_RULES_DIR=./rules"
  echo "MASP_WORKER_ENGINE_KEYS=static_metadata,clamav,yara"
  echo "MASP_WORKER_ENROLLMENT_TOKEN=CHANGE_ME_LONG_RANDOM_WORKER_ENROLLMENT_TOKEN"
  echo "MASP_SIEM_WEBHOOK_URL=https://user:WEBHOOK-PASS@siem.example/hook"
} > "$old/.env.pilot"
cp "$old/.env.pilot" "$work/old-env-before"
{
  echo '#!/usr/bin/env bash'
  echo 'echo "old-backup $*" >> "$FAKE_DOCKER_LOG"'
  echo 'out="${@: -1}"; dir="$out/masp-pilot-20261002T000000Z"; mkdir -p "$dir"; echo dump > "$dir/db.dump"'
  echo '(cd "$dir" && sha256sum db.dump > SHA256SUMS)'
} > "$old/deploy/pilot/backup.sh"
printf '#!/usr/bin/env bash\necho "old-verify" >> "$FAKE_DOCKER_LOG"\n' > "$old/deploy/pilot/verify.sh"
printf 'masp-pilot:0.1.0-pilot.6\nclamav/clamav:stable\n' > "$work/images"
[[ "$3" == "images missing" ]] || echo postgres:16-alpine >> "$work/images"
if [[ "$4" == "rules taken" ]]; then mkdir -p "$work/srv/rules"; echo x > "$work/srv/rules/other.yar"; fi
echo fake-image > "$work/opt/masp-pilot-0.1.0-pilot.11-image.tar"
(cd "$work/opt" && sha256sum masp-pilot-0.1.0-pilot.11-image.tar > masp-pilot-0.1.0-pilot.11-image.tar.sha256)
export FAKE_DOCKER_LOG="$work/docker.log" FAKE_IMAGES="$work/images" FAKE_BINDING="$2"
cp "$FAKE_DOCKER" "$work/bin/docker"
printf '#!/usr/bin/env bash\necho Linux\n' > "$work/bin/uname"
printf '#!/usr/bin/env bash\nexit 3\n' > "$work/bin/systemctl"
chmod +x "$work/bin/"*
export PATH="$work/bin:$PATH"
ln -s "$old" "$work/opt/current"
MASP_UPGRADE_REQUIRE_ROOT=0 MASP_INSTALL_ROOT="$work/opt" MASP_DATA_ROOT="$work/srv" MASP_WRAPPER="$work/bin/masp" \
  MASP_UPGRADE_LOG="$work/upgrade.log" bash "$new/deploy/pilot/upgrade.sh" $1 2>&1
echo "EXIT=$?"
echo "--- docker"; cat "$FAKE_DOCKER_LOG"
echo "--- new env"; cat "$new/.env.pilot" 2>/dev/null
echo "--- rules"; ls "$work/srv/rules" 2>/dev/null
echo "--- old env unchanged"; cmp -s "$old/.env.pilot" "$work/old-env-before" && echo yes
"""

# Records every call; knows which images are loaded and answers the few
# questions upgrade.sh, install.sh and verify.sh ask.
UPGRADE_FAKE_DOCKER = r"""#!/usr/bin/env bash
printf '%s\n' "$*" >> "$FAKE_DOCKER_LOG"
case "$*" in
  "image inspect "*) grep -qxF "$3" "$FAKE_IMAGES"; exit ;;
  "load -i "*) echo masp-pilot:0.1.0-pilot.11 >> "$FAKE_IMAGES" ;;
  "ps "*) echo c1; echo c2 ;;
  "network inspect "*) echo 172.18.0.1 ;;
  *" config --images"*) env_file="${*##*--env-file }"; env_file="${env_file%% *}"
     sed -n 's/^MASP_IMAGE=//p' "$env_file"; echo postgres:16-alpine; echo clamav/clamav:stable ;;
  *"exec -T icap python -c"*) printf 'MASP DB pool enabled (min=0, max=4)\nMASP_ICAP_BINDING|%s\n' "$FAKE_BINDING" ;;
esac
exit 0
"""

BOUND = "client|fil||File gateway"


@unittest.skipUnless(POSIX_BASH, "requires a POSIX bash (Git Bash on Windows)")
class PilotUpgradeTests(unittest.TestCase):
    def upgrade(self, args: str, binding: str = BOUND, images: str = "", rules: str = "") -> dict[str, str]:
        with tempfile.TemporaryDirectory() as scratch:
            fake = Path(scratch) / "docker"
            fake.write_bytes(UPGRADE_FAKE_DOCKER.encode())
            result = subprocess.run([BASH, "-c", UPGRADE_HARNESS, "harness", args, binding, images, rules],
                                    capture_output=True, text=True, timeout=180,
                                    env={"ROOT": ROOT.as_posix(), "PATH": os.environ["PATH"],
                                         "FAKE_DOCKER": fake.as_posix()})
        sections = {"output": ""}
        name = "output"
        for line in result.stdout.splitlines():
            if line.startswith("--- "):
                name = line[4:]
                sections[name] = ""
            else:
                sections[name] += line + "\n"
        return sections

    def test_dry_run_shows_the_carried_settings_and_changes_nothing(self) -> None:
        out = self.upgrade("--dry-run")
        self.assertIn("EXIT=0", out["output"])
        self.assertIn("Dry run: nothing was changed", out["output"])
        self.assertIn("> MASP_IMAGE=masp-pilot:0.1.0-pilot.11", out["output"])
        self.assertIn("> MASP_WORKER_ENGINE_KEYS=static_metadata,clamav,yara,file_type,hash_list", out["output"])
        self.assertIn("Would copy the rules", out["output"])
        # Secrets and URL credentials never reach the screen or the log.
        for secret in ("OLD-SECRET-API-TOKEN", "WEBHOOK-PASS", "old-admin-password-long"):
            self.assertNotIn(secret, out["output"])
        self.assertEqual(out["new env"], "")
        self.assertNotIn("old-backup", out["docker"])
        self.assertFalse(any(" up -d" in line for line in out["docker"].splitlines()))
        self.assertNotIn("current ->", out["output"])

    def test_upgrade_backs_up_first_carries_settings_and_switches(self) -> None:
        out = self.upgrade("--yes --skip-current-verify")
        self.assertIn("EXIT=0", out["output"])
        calls = out["docker"].splitlines()
        backup = next(i for i, call in enumerate(calls) if call.startswith("old-backup"))
        up = next(i for i, call in enumerate(calls) if " up -d --wait" in call)
        self.assertLess(backup, up)
        self.assertIn("masp-pilot-0.1.0-pilot.11/docker-compose.pilot.yml", calls[up])
        self.assertTrue(any(call.startswith("load -i") for call in calls[:backup]))
        env = out["new env"]
        for kept in ("MASP_ICAP_SERVICE_CLIENT_KEY=fil", "OLD-SECRET-API-TOKEN", "WEBHOOK-PASS"):
            self.assertIn(kept, env)
        self.assertIn("MASP_IMAGE=masp-pilot:0.1.0-pilot.11\n", env)
        self.assertIn("MASP_WORKER_ENROLLMENT_TOKEN=\n", env)
        self.assertNotIn("MASP_RULES_DIR=./rules", env)
        self.assertNotIn("CHANGE_ME", env)
        # Settings the old file lacked arrive once, from the example; no proxy here.
        self.assertEqual(env.count("MASP_SESSION_SECURE="), 1)
        self.assertIn("MASP_SESSION_SECURE=\n", env)
        self.assertIn("MASP_FORWARDED_ALLOW_IPS=127.0.0.1\n", env)
        self.assertEqual(out["rules"].split(), ["custom.yar"])
        # Git Bash copies instead of linking, so the switch is read from the script's own report.
        self.assertRegex(out["output"], r"opt/current -> \S*/masp-pilot-0\.1\.0-pilot\.11\n")
        self.assertIn("yes", out["old env unchanged"])
        self.assertIn("ICAP scans are filed under service client File gateway (fil).", out["output"])
        self.assertIn("restore.sh --env-file .env.pilot --backup-dir", out["output"])

    def test_a_failure_after_the_backup_prints_the_rollback(self) -> None:
        out = self.upgrade("--yes --skip-current-verify", binding="unresolved|fil|No service client has the key fil.|")
        self.assertIn("EXIT=1", out["output"])
        self.assertIn("ICAP client key 'fil' does not resolve", out["output"])
        self.assertIn("To return to 0.1.0-pilot.6, run:", out["output"])
        self.assertIn("masp-pilot-20261002T000000Z", out["output"])
        self.assertIn("yes", out["old env unchanged"])

    def test_a_missing_image_stops_before_the_backup(self) -> None:
        out = self.upgrade("--yes --skip-current-verify", images="images missing")
        self.assertIn("EXIT=1", out["output"])
        self.assertIn("image postgres:16-alpine is not on this host", out["output"])
        self.assertNotIn("old-backup", out["docker"])
        self.assertNotIn("To return to", out["output"])
        self.assertEqual(out["new env"], "")

    def test_rules_inside_the_old_release_are_not_merged_silently(self) -> None:
        out = self.upgrade("--yes --skip-current-verify", rules="rules taken")
        self.assertIn("EXIT=1", out["output"])
        self.assertIn("already has files", out["output"])
        self.assertNotIn("old-backup", out["docker"])
