#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
BACKUP_DIR=""
CONFIRMED=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            [[ $# -ge 2 ]] || pilot_die "--env-file requires a path"
            ENV_FILE="$2"
            shift 2
            ;;
        --backup-dir)
            [[ $# -ge 2 ]] || pilot_die "--backup-dir requires a path"
            BACKUP_DIR="$2"
            shift 2
            ;;
        --yes)
            CONFIRMED=1
            shift
            ;;
        *)
            pilot_die "usage: restore.sh --backup-dir PATH [--env-file PATH] --yes"
            ;;
    esac
done

[[ $CONFIRMED -eq 1 ]] || pilot_die "restore is destructive; rerun with --yes"
[[ -n "$BACKUP_DIR" && -d "$BACKUP_DIR" ]] || pilot_die "backup directory missing"
pilot_init "$ENV_FILE"
pilot_require_command docker
pilot_require_command tar
pilot_require_command sha256sum

(
    cd "$BACKUP_DIR"
    sha256sum -c SHA256SUMS
)

archive="$BACKUP_DIR/storage.tar.gz"
rules_archive="$BACKUP_DIR/rules.tar.gz"
dump="$BACKUP_DIR/postgres.dump"
if tar -tzf "$archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    pilot_die "storage archive contains an unsafe path"
fi
if tar -tzf "$rules_archive" | grep -Eq '(^/|(^|/)\.\.(/|$))'; then
    pilot_die "rules archive contains an unsafe path"
fi

storage_dir="$(pilot_storage_dir)"
rules_dir="$(pilot_rules_dir)"
[[ ! -L "$storage_dir" ]] || pilot_die "refusing symlink storage directory"
[[ ! -L "$rules_dir" ]] || pilot_die "refusing symlink rules directory"
previous_storage="${storage_dir}.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"
previous_rules="${rules_dir}.pre-restore.$(date -u +%Y%m%dT%H%M%SZ)"

restart_services() {
    pilot_compose start app worker icap >/dev/null 2>&1 || true
}
trap restart_services EXIT

pilot_compose stop app worker icap
pilot_compose exec -T postgres dropdb -U masp --if-exists masp
pilot_compose exec -T postgres createdb -U masp -O masp masp
pilot_compose exec -T postgres pg_restore -U masp -d masp --no-owner --no-privileges < "$dump"

if [[ -d "$storage_dir" ]]; then
    mv "$storage_dir" "$previous_storage"
fi
pilot_prepare_data_dir "$storage_dir"
tar -C "$storage_dir" -xzf "$archive"
if [[ -d "$rules_dir" ]]; then
    mv "$rules_dir" "$previous_rules"
fi
pilot_prepare_data_dir "$rules_dir"
tar -C "$rules_dir" -xzf "$rules_archive"

restart_services
trap - EXIT
printf 'Restore completed. Previous storage retained at %s\n' "$previous_storage"
printf 'Previous rules retained at %s\n' "$previous_rules"
