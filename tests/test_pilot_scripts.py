"""Behaviour of the pilot backup/restore scripts against a recording fake docker."""
import os
import shutil
import subprocess
import sys
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


if __name__ == "__main__":
    unittest.main()
