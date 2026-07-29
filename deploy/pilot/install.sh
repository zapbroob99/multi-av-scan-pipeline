#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
NO_BUILD=0
DRY_RUN=0

usage() {
    cat <<'EOF'
Usage: deploy/pilot/install.sh [--env-file PATH] [--no-build] [--dry-run]

  --no-build  Use already loaded/pulled MASP images.
  --dry-run   Validate configuration and print the compose command only.
EOF
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --env-file)
            [[ $# -ge 2 ]] || pilot_die "--env-file requires a path"
            ENV_FILE="$2"
            shift 2
            ;;
        --no-build)
            NO_BUILD=1
            shift
            ;;
        --dry-run)
            DRY_RUN=1
            shift
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            pilot_die "unknown argument: $1"
            ;;
    esac
done

[[ "$(uname -s)" == "Linux" ]] || pilot_die "the pilot bundle must be installed on Linux"
pilot_init "$ENV_FILE"
pilot_require_command docker
docker compose version >/dev/null
docker info >/dev/null

db_password="$(pilot_env_value MASP_POSTGRES_PASSWORD)"
api_token="$(pilot_env_value MASP_API_TOKEN)"
admin_password="$(pilot_env_value MASP_ADMIN_PASSWORD)"
icap_bind="$(pilot_env_value MASP_ICAP_BIND)"
icap_allowlist="$(pilot_env_value MASP_ICAP_ALLOWED_IPS)"
storage_dir="$(pilot_storage_dir)"
rules_dir="$(pilot_rules_dir)"

[[ "$db_password" =~ ^[A-Za-z0-9_-]{24,}$ ]] || \
    pilot_die "MASP_POSTGRES_PASSWORD must be a URL-safe value of at least 24 characters"
[[ "$db_password" != CHANGE_ME* ]] || pilot_die "replace MASP_POSTGRES_PASSWORD"
[[ ${#api_token} -ge 32 ]] || pilot_die "MASP_API_TOKEN must be at least 32 characters"
[[ "$api_token" != CHANGE_ME* ]] || pilot_die "replace MASP_API_TOKEN"
[[ ${#admin_password} -ge 12 ]] || pilot_die "MASP_ADMIN_PASSWORD must be at least 12 characters"
[[ "$admin_password" != CHANGE_ME* ]] || pilot_die "replace MASP_ADMIN_PASSWORD"
[[ -n "$icap_bind" ]] || pilot_die "MASP_ICAP_BIND is empty"
[[ -n "$icap_allowlist" ]] || pilot_die "MASP_ICAP_ALLOWED_IPS is empty"

if [[ "$icap_bind" != 127.0.0.1:* && "$icap_allowlist" == "127.0.0.1" ]]; then
    pilot_die "add the approved storage client IPs to MASP_ICAP_ALLOWED_IPS"
fi

umask 077
chmod 600 "$PILOT_ENV_FILE"
pilot_prepare_data_dir "$storage_dir"
pilot_prepare_data_dir "$storage_dir/samples"
[[ -d "$rules_dir" ]] || pilot_die "rules directory missing: $rules_dir"
# The admin UI adds and removes YARA rule files, so the rules mount must also be
# writable by the unprivileged container id.
pilot_prepare_data_dir "$rules_dir"

pilot_compose config --quiet

if [[ $DRY_RUN -eq 1 ]]; then
    printf 'Configuration is valid. Would run:\n  '
    printf '%q ' "${PILOT_COMPOSE[@]}" up -d --wait --wait-timeout 600
    [[ $NO_BUILD -eq 1 ]] && printf '%q ' --no-build || printf '%q ' --build
    printf '\n'
    exit 0
fi

up_args=(up -d --wait --wait-timeout 600)
[[ $NO_BUILD -eq 1 ]] && up_args+=(--no-build) || up_args+=(--build)
pilot_compose "${up_args[@]}"

printf '\nMASP pilot is running. Verify it with:\n'
printf '  %q --env-file %q\n' "$PILOT_SCRIPT_DIR/verify.sh" "$PILOT_ENV_FILE"
