#!/usr/bin/env bash
#
# install-masp-eset-worker.sh — provision a MASP worker dedicated to the ESET
# Server Security for Linux engine on a corporate test VM.
#
# Scope (Stage A): idempotent provisioning of the WORKER side only.
#   - Runs the worker as a dedicated unprivileged system user.
#   - Creates a Python venv and installs MASP requirements.
#   - Creates a root-owned 0600 environment file with placeholders (NO secrets
#     on the command line); the admin fills it in with `sudoedit`.
#   - Installs and enables a systemd service.
#   - Runs preflight + post-install health checks (DB, storage, odscan) AS the
#     unprivileged worker user.
#
# It DOES NOT install ESET, manage ESET licensing, or write malware. odscan is
# only checked for presence. Re-running is safe and non-destructive: an existing
# environment file is preserved, never overwritten.
#
# Usage:
#   sudo ./install-masp-eset-worker.sh --dry-run   # print actions only
#   sudo ./install-masp-eset-worker.sh             # provision
#   sudoedit /etc/masp/eset-worker.env             # then fill in DB URL etc.
#
set -euo pipefail

# ---- configuration (override via environment; NO secrets here) ---------------
ESET_WORKER_USER="${MASP_ESET_USER:-masp-eset}"
MASP_ROOT="${MASP_ROOT:-/opt/masp}"
VENV_DIR="${MASP_VENV_DIR:-${MASP_ROOT}/.venv}"
ENV_DIR="${MASP_ENV_DIR:-/etc/masp}"
ENV_FILE="${ENV_DIR}/eset-worker.env"
SERVICE_NAME="${MASP_ESET_SERVICE:-masp-eset-worker}"
SERVICE_FILE="/etc/systemd/system/${SERVICE_NAME}.service"
ODSCAN_PATH="${MASP_ODSCAN_PATH:-/opt/eset/efs/bin/odscan}"
ENGINE_KEY="eset_server_security_linux_cli"
DRY_RUN=0

log()  { printf '[install] %s\n' "$*"; }
warn() { printf '[install][warn] %s\n' "$*" >&2; }
die()  { printf '[install][error] %s\n' "$*" >&2; exit 1; }

# Run a command, or print it under --dry-run. No eval: arguments stay a list, so
# no word-splitting/quoting surprises.
run() {
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '[dry-run]'; printf ' %q' "$@"; printf '\n'
  else
    "$@"
  fi
}

# Read one value from the restricted systemd EnvironmentFile format used by
# this installer. shlex removes optional outer quotes without shell expansion,
# so password characters such as $, backticks, and & remain data. Never source
# this file: systemd EnvironmentFile syntax is not shell code.
read_env_value() {
  python3 - "${ENV_FILE}" "$1" <<'PY'
import shlex
import sys

path, wanted = sys.argv[1:]
value = ""
with open(path, encoding="utf-8") as handle:
    for raw_line in handle:
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        key, separator, raw_value = line.partition("=")
        if separator and key.strip() == wanted:
            candidate = raw_value.strip()
            if candidate[:1] in {"'", '"'}:
                try:
                    parts = shlex.split(candidate, comments=False, posix=True)
                except ValueError as exc:
                    raise SystemExit(f"invalid quoted value for {wanted}: {exc}")
                if len(parts) != 1:
                    raise SystemExit(f"invalid quoted value for {wanted}")
                candidate = parts[0]
            value = candidate
print(value)
PY
}

run_as_worker() {
  # Drop privileges directly so post-checks get a deterministic, minimal
  # environment. Secrets are inherited by this wrapper and copied into the
  # child's environment; they are never placed in command-line arguments.
  python3 - "${ESET_WORKER_USER}" "$@" <<'PY'
import os
import pwd
import sys

username, *argv = sys.argv[1:]
if not argv:
    raise SystemExit("missing worker command")

account = pwd.getpwnam(username)
child_env = {
    "HOME": account.pw_dir,
    "USER": account.pw_name,
    "LOGNAME": account.pw_name,
    "PATH": os.defpath,
    "LANG": os.environ.get("LANG", "C.UTF-8"),
}
for key in ("MASP_DATABASE_URL", "MASP_SAMPLE_PATH_MAPPINGS_JSON"):
    if key in os.environ:
        child_env[key] = os.environ[key]

os.initgroups(account.pw_name, account.pw_gid)
os.setgid(account.pw_gid)
os.setuid(account.pw_uid)
os.execvpe(argv[0], argv, child_env)
PY
}

usage() {
  sed -n '2,33p' "$0"
  exit 0
}

# ---- argument parsing --------------------------------------------------------
while [ $# -gt 0 ]; do
  case "$1" in
    --dry-run) DRY_RUN=1 ;;
    -h|--help) usage ;;
    *) die "Unknown argument: $1" ;;
  esac
  shift
done

# ---- preflight ---------------------------------------------------------------
log "Preflight checks..."

if [ "$(uname -s)" != "Linux" ]; then
  die "This installer targets Linux (systemd). Detected: $(uname -s)."
fi

if [ "${DRY_RUN}" -eq 0 ] && [ "$(id -u)" -ne 0 ]; then
  die "Must run as root (creates a user, systemd unit). Re-run with sudo, or use --dry-run."
fi

command -v python3 >/dev/null 2>&1 || die "python3 not found."
command -v systemctl >/dev/null 2>&1 || warn "systemctl not found; service install will be skipped."

[ -d "${MASP_ROOT}" ] || die "MASP_ROOT '${MASP_ROOT}' does not exist. Deploy the MASP release there first."
[ -f "${MASP_ROOT}/requirements.txt" ] || die "requirements.txt not found under MASP_ROOT '${MASP_ROOT}'."

# odscan presence is checked but NOT installed/licensed by this script.
if [ -x "${ODSCAN_PATH}" ]; then
  log "Found odscan at ${ODSCAN_PATH}."
else
  warn "odscan not found at ${ODSCAN_PATH}. Install ESET Server Security for Linux"
  warn "separately; the worker will report the engine unavailable until then."
fi

# ---- 1. dedicated unprivileged system user -----------------------------------
if id "${ESET_WORKER_USER}" >/dev/null 2>&1; then
  log "User ${ESET_WORKER_USER} already exists."
else
  log "Creating system user ${ESET_WORKER_USER}."
  run useradd --system --no-create-home --shell /usr/sbin/nologin "${ESET_WORKER_USER}"
fi

# ---- 2. python venv + requirements (idempotent) ------------------------------
if [ -x "${VENV_DIR}/bin/python" ]; then
  log "Virtualenv already present at ${VENV_DIR}."
else
  log "Creating virtualenv at ${VENV_DIR}."
  run python3 -m venv "${VENV_DIR}"
fi
log "Installing/updating MASP requirements."
run "${VENV_DIR}/bin/pip" install --upgrade pip
run "${VENV_DIR}/bin/pip" install -r "${MASP_ROOT}/requirements.txt"

# ---- 3. root-owned 0600 environment file (preserved if present) --------------
run mkdir -p "${ENV_DIR}"
if [ -f "${ENV_FILE}" ]; then
  log "Environment file ${ENV_FILE} exists; preserving it. Edit with: sudoedit ${ENV_FILE}"
else
  log "Creating placeholder environment file ${ENV_FILE} (root:root 0600, no secrets)."
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '[dry-run] write placeholder %s (root:root 0600) with MASP_WORKER_ENGINE_KEYS=%s\n' \
      "${ENV_FILE}" "${ENGINE_KEY}"
  else
    install -m 0600 -o root -g root /dev/null "${ENV_FILE}"
    cat > "${ENV_FILE}" <<EOF
# MASP ESET worker environment. Created by install-masp-eset-worker.sh.
# Root-owned, 0600. Fill in with: sudoedit ${ENV_FILE}
# Do NOT pass the DB password on any command line.
MASP_DATABASE_URL='postgresql://REPLACE_ME'
MASP_WORKER_ENGINE_KEYS=${ENGINE_KEY}
MASP_ODSCAN_PATH=${ODSCAN_PATH}
MASP_DB_POOL_ENABLED=1
# Map the DB-stored sample prefix to this VM's shared storage mount.
# Quote the JSON in single quotes for systemd EnvironmentFile, e.g.:
# MASP_SAMPLE_PATH_MAPPINGS_JSON='{"/app/storage/samples":"/mnt/masp-storage/samples"}'
MASP_SAMPLE_PATH_MAPPINGS_JSON=''
EOF
    log "Placeholder written. Fill it in with: sudoedit ${ENV_FILE}"
  fi
fi
run chown root:root "${ENV_FILE}"
run chmod 0600 "${ENV_FILE}"

# ---- 4. systemd service ------------------------------------------------------
# systemd (pid 1, root) reads the root-owned EnvironmentFile and passes it to the
# service, so the worker user never needs to read the secret file directly.
if command -v systemctl >/dev/null 2>&1; then
  log "Installing systemd unit ${SERVICE_FILE}."
  if [ "${DRY_RUN}" -eq 1 ]; then
    printf '[dry-run] write %s (User=%s, ExecStart=%s -m app.workers.scan_worker)\n' \
      "${SERVICE_FILE}" "${ESET_WORKER_USER}" "${VENV_DIR}/bin/python"
  else
    cat > "${SERVICE_FILE}" <<EOF
[Unit]
Description=MASP ESET Server Security worker
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=${ESET_WORKER_USER}
Group=${ESET_WORKER_USER}
EnvironmentFile=${ENV_FILE}
WorkingDirectory=${MASP_ROOT}
ExecStart=${VENV_DIR}/bin/python -m app.workers.scan_worker
Restart=on-failure
RestartSec=5
NoNewPrivileges=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=${MASP_ROOT}

[Install]
WantedBy=multi-user.target
EOF
  fi
  run systemctl daemon-reload
  run systemctl enable "${SERVICE_NAME}"
  log "Service installed. Start it with: systemctl start ${SERVICE_NAME}"
else
  warn "Skipping systemd unit (systemctl unavailable)."
fi

# ---- 5. post-install health checks (AS the worker user) ----------------------
log "Post-install checks (as ${ESET_WORKER_USER})..."
if [ "${DRY_RUN}" -eq 1 ]; then
  log "[dry-run] would verify DB reachability, storage readability, and odscan as ${ESET_WORKER_USER}."
else
  database_url="$(read_env_value MASP_DATABASE_URL)"
  mappings_json="$(read_env_value MASP_SAMPLE_PATH_MAPPINGS_JSON)"
  configured_odscan="$(read_env_value MASP_ODSCAN_PATH)"
  configured_odscan="${configured_odscan:-${ODSCAN_PATH}}"

  # Values reach child processes through the environment, never through argv.
  export MASP_DATABASE_URL="${database_url}"
  export MASP_SAMPLE_PATH_MAPPINGS_JSON="${mappings_json}"

  # odscan must be executable by the worker user.
  if run_as_worker test -x "${configured_odscan}"; then
    log "odscan executable by ${ESET_WORKER_USER}."
  else
    warn "odscan not executable by ${ESET_WORKER_USER} at ${configured_odscan}."
  fi

  # DB reachability via the same code path the worker uses.
  if [ -z "${database_url}" ] || [ "${database_url}" = "postgresql://REPLACE_ME" ]; then
    warn "MASP_DATABASE_URL not filled in yet. Run 'sudoedit ${ENV_FILE}', then re-run this script."
  elif (cd "${MASP_ROOT}" && run_as_worker \
        "${VENV_DIR}/bin/python" -c "from app.database import connect
with connect() as c:
    c.execute('SELECT 1')
print('db-ok')") 2>/dev/null | grep -q db-ok; then
    log "Database reachable as ${ESET_WORKER_USER}."
  else
    warn "Database check failed as ${ESET_WORKER_USER}. Verify MASP_DATABASE_URL and grants."
  fi

  # Storage mount readability: each mapping target must be readable by the worker.
  if [ -n "${mappings_json}" ]; then
    if roots="$("${VENV_DIR}/bin/python" -c "import json, os
try:
    data = json.loads(os.environ['MASP_SAMPLE_PATH_MAPPINGS_JSON'])
    for target in data.values():
        print(target)
except Exception as exc:
    raise SystemExit(str(exc))")"; then
      if [ -n "${roots}" ]; then
        printf '%s\n' "${roots}" | while IFS= read -r root; do
          [ -n "${root}" ] || continue
          if run_as_worker test -r "${root}"; then
            log "Storage root readable by worker: ${root}"
          else
            warn "Storage root NOT readable by ${ESET_WORKER_USER}: ${root}"
          fi
        done
      else
        warn "MASP_SAMPLE_PATH_MAPPINGS_JSON is set but contains no targets."
      fi
    else
      warn "MASP_SAMPLE_PATH_MAPPINGS_JSON is invalid; fix it before starting the worker."
    fi
  fi
fi

log "Done. Review ${ENV_FILE} (sudoedit), then: systemctl start ${SERVICE_NAME} && journalctl -u ${SERVICE_NAME} -f"
log "The worker advertises engine key '${ENGINE_KEY}'; enable the engine in the MASP admin UI after verifying health."
