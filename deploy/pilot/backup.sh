#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
OUTPUT_ROOT="${MASP_PILOT_BACKUP_DIR:-$PILOT_ROOT_DIR/backups}"

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            [[ $# -ge 2 ]] || pilot_die "--env-file requires a path"
            ENV_FILE="$2"
            shift 2
            ;;
        --output-dir)
            [[ $# -ge 2 ]] || pilot_die "--output-dir requires a path"
            OUTPUT_ROOT="$2"
            shift 2
            ;;
        *)
            pilot_die "usage: backup.sh [--env-file PATH] [--output-dir PATH]"
            ;;
    esac
done

pilot_init "$ENV_FILE"
pilot_require_command docker
pilot_require_command tar
pilot_require_command sha256sum
storage_dir="$(pilot_storage_dir)"
rules_dir="$(pilot_rules_dir)"
[[ -d "$storage_dir" ]] || pilot_die "storage directory missing: $storage_dir"
[[ -d "$rules_dir" ]] || pilot_die "rules directory missing: $rules_dir"

umask 077
timestamp="$(date -u +%Y%m%dT%H%M%SZ)"
backup_dir="$OUTPUT_ROOT/masp-pilot-$timestamp"
mkdir -p "$backup_dir"

# Every running writer, including deferred/manifest intake and notification
# workers, must stop: a writer left running changes the database or storage
# while it is dumped, or overwrites the data just restored.
mapfile -t writers < <(pilot_running_writer_containers)
restart_services() {
    pilot_resume_writers "${writers[@]}"
}
trap restart_services EXIT

pilot_pause_writers "${writers[@]}"
pilot_compose exec -T postgres pg_dump -U masp -d masp -Fc > "$backup_dir/postgres.dump"
tar -C "$storage_dir" -czf "$backup_dir/storage.tar.gz" .
tar -C "$rules_dir" -czf "$backup_dir/rules.tar.gz" .
printf 'created_at=%s\nproject=%s\n' "$timestamp" "$PILOT_PROJECT" > "$backup_dir/METADATA"
(
    cd "$backup_dir"
    sha256sum postgres.dump storage.tar.gz rules.tar.gz METADATA > SHA256SUMS
)

restart_services
trap - EXIT
printf 'Backup written to %s\n' "$backup_dir"
printf 'Store .env.pilot separately in the approved secret-management system.\n'
