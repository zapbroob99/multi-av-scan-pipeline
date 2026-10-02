#!/usr/bin/env bash
# Upgrade an installed MASP pilot to this release on a host with no internet
# access. Run it as root from the extracted bundle of the NEW release.
#
# It finds the running release through /opt/masp/current (or --from), checks
# it, loads the new image, carries .env.pilot over (adding only the settings the
# old file lacks), validates the result, backs up with the old release's own
# backup.sh, installs, switches /opt/masp/current and the masp command, and runs
# the acceptance checks. The old release directory is never modified. Nothing is
# rolled back automatically: when a step after the backup fails, the exact
# rollback command is printed.
#
# Usage: deploy/pilot/upgrade.sh [--image FILE] [--from DIR] [--backup-root DIR]
#          [--skip-current-verify] [--dry-run] [--yes]
#
#   --image FILE            masp-pilot-<version>-image.tar (or -images.tar) with its
#                           .sha256 beside it; looked up next to the bundle and in
#                           /tmp when omitted. Not needed if the image is loaded.
#   --from DIR              the running release (default: /opt/masp/current)
#   --backup-root DIR       where the backup goes (default: /srv/masp/backups)
#   --skip-current-verify   upgrade even if the running release fails its own checks
#   --dry-run               show what would change; nothing running is changed
#                           (install.sh's validation still sets data directory owners)
#   --yes                   do not ask for confirmation
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
PROJECT="${MASP_PILOT_PROJECT:-masp-pilot}"
INSTALL_ROOT="${MASP_INSTALL_ROOT:-/opt/masp}"
DATA_ROOT="${MASP_DATA_ROOT:-/srv/masp}"
WRAPPER="${MASP_WRAPPER:-/usr/local/bin/masp}"
LOG_FILE="${MASP_UPGRADE_LOG:-/var/log/masp-upgrade.log}"

IMAGE_TAR=""
FROM=""
BACKUP_ROOT=""
SKIP_CURRENT_VERIFY=0
DRY_RUN=0
ASSUME_YES=0
BACKUP_DIR=""

usage() {
    sed -n '2,25p' "$0" | sed 's/^# \{0,1\}//'
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --image) IMAGE_TAR="${2:-}"; shift 2 ;;
        --from) FROM="${2:-}"; shift 2 ;;
        --backup-root) BACKUP_ROOT="${2:-}"; shift 2 ;;
        --skip-current-verify) SKIP_CURRENT_VERIFY=1; shift ;;
        --dry-run) DRY_RUN=1; shift ;;
        --yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done
BACKUP_ROOT="${BACKUP_ROOT:-$DATA_ROOT/backups}"

rollback_hint() {
    [[ -n "$BACKUP_DIR" ]] || return 0
    printf '\nThe running release may now be the new one. To return to %s, run:\n' "$OLD_VERSION" >&2
    printf '  cd %q && ./deploy/pilot/install.sh --env-file .env.pilot --no-build && ./deploy/pilot/restore.sh --env-file .env.pilot --backup-dir %q --yes && ln -sfn %q %q/current\n' \
        "$FROM" "$BACKUP_DIR" "$FROM" "$INSTALL_ROOT" >&2
    printf 'then, after a minute: %q/deploy/pilot/verify.sh --env-file %q/.env.pilot\n' "$FROM" "$FROM" >&2
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    rollback_hint
    [[ $DRY_RUN -eq 1 ]] || printf 'The full log is in %s.\n' "$LOG_FILE" >&2
    exit 1
}

STEP=0
step() {
    STEP=$((STEP + 1))
    printf '\n==> [%s/9] %s\n' "$STEP" "$*"
}

note() {
    printf '    %s\n' "$*"
}

if [[ $DRY_RUN -eq 0 ]]; then
    # MASP_UPGRADE_REQUIRE_ROOT=0 exists for the script's tests only.
    [[ $EUID -eq 0 || "${MASP_UPGRADE_REQUIRE_ROOT:-1}" == 0 ]] || { echo "Run as root (sudo -i first)." >&2; exit 1; }
    mkdir -p "$(dirname "$LOG_FILE")"
    exec > >(tee -a "$LOG_FILE") 2>&1
fi
# Hardened hosts run root with umask 027 or 077; files this script creates for
# the containers must stay readable. Secrets get explicit modes below.
umask 022
printf '\n===== MASP upgrade %s%s =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$([[ $DRY_RUN -eq 1 ]] && echo ' (dry run)')"

env_value() {
    sed -n "s/^$1=//p" "$2" | tail -n 1 | tr -d '\r'
}

has_key() {
    grep -q "^$1=" "$2"
}

set_env() {
    local key="$1" value="$2" file="$3" tmp
    tmp="$(mktemp "$file.XXXXXX")"
    # awk through ENVIRON, not sed or -v: values may contain any character.
    KEY="$key" VALUE="$value" awk 'BEGIN { key = ENVIRON["KEY"]; value = ENVIRON["VALUE"]; done = 0 }
        index($0, key "=") == 1 { if (!done) print key "=" value; done = 1; next }
        { print }
        END { if (!done) print key "=" value }' "$file" > "$tmp"
    cat "$tmp" > "$file"
    rm -f "$tmp"
}

# Values of these settings, and credentials inside URLs, are never printed.
masked() {
    sed -E -e 's/^([A-Z0-9_]*(PASSWORD|_TOKEN|_SECRET|ENCRYPTION_KEY|API_KEY))=.+/\1=<set>/' \
           -e 's#://[^/@[:space:]]*@#://<credentials>@#' "$1"
}

release_version() {
    sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$1/RELEASE.json" 2>/dev/null | head -n 1
}

proxy_in_front() {
    command -v systemctl >/dev/null 2>&1 && systemctl is-active --quiet nginx 2>/dev/null
}

# ---------------------------------------------------------------------------
step "Checking this release"
[[ -f "$BUNDLE_DIR/RELEASE.json" && -f "$BUNDLE_DIR/docker-compose.pilot.yml" ]] || \
    die "run this script from an extracted release bundle"
NEW_VERSION="$(release_version "$BUNDLE_DIR")"
[[ -n "$NEW_VERSION" ]] || die "cannot read the release version from RELEASE.json"
for command in docker sha256sum sed awk grep; do
    command -v "$command" >/dev/null || die "required command missing: $command"
done
if [[ -f "$BUNDLE_DIR/SHA256SUMS" ]]; then
    (cd "$BUNDLE_DIR" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1) || \
        die "the bundle does not match its SHA256SUMS; extract the release ZIP again"
    note "Bundle checksums OK"
fi
note "New release: $NEW_VERSION ($BUNDLE_DIR)"

# ---------------------------------------------------------------------------
step "Finding the running release"
if [[ -z "$FROM" ]]; then
    [[ -e "$INSTALL_ROOT/current" ]] || \
        die "$INSTALL_ROOT/current does not exist; pass --from with the running release's directory"
    FROM="$INSTALL_ROOT/current"
fi
[[ -d "$FROM" ]] || die "not a directory: $FROM"
FROM="$(cd "$FROM" && pwd -P)"
[[ -f "$FROM/.env.pilot" ]] || die "no .env.pilot in $FROM"
[[ -x "$FROM/deploy/pilot/backup.sh" || -f "$FROM/deploy/pilot/backup.sh" ]] || die "no deploy/pilot/backup.sh in $FROM"
if [[ "$FROM" == "$(cd "$BUNDLE_DIR" && pwd -P)" ]]; then
    die "$NEW_VERSION is already the current release. To check it, run ./deploy/pilot/verify.sh --env-file .env.pilot"
fi
OLD_VERSION="$(release_version "$FROM")"
OLD_VERSION="${OLD_VERSION:-$(env_value MASP_IMAGE "$FROM/.env.pilot")}"
running="$(docker ps --filter "label=com.docker.compose.project=$PROJECT" --filter status=running -q | wc -l | tr -d ' ')"
[[ "$running" -gt 0 ]] || \
    die "no running containers in project $PROJECT. If it has another name, run: docker compose ls, then export MASP_PILOT_PROJECT=<name>"
note "Running release: $OLD_VERSION ($FROM), $running container(s) in $PROJECT"

if [[ $SKIP_CURRENT_VERIFY -eq 1 || $DRY_RUN -eq 1 ]]; then
    note "Not checking the running release ($([[ $DRY_RUN -eq 1 ]] && echo dry run || echo --skip-current-verify))"
else
    note "Running its own acceptance checks first"
    (cd "$FROM" && bash ./deploy/pilot/verify.sh --env-file .env.pilot) || \
        die "the running release fails its own checks, so a failure after the upgrade could not be told apart from an existing one. Fix it first, or rerun with --skip-current-verify"
fi

# ---------------------------------------------------------------------------
step "The new image"
NEW_IMAGE="masp-pilot:$NEW_VERSION"
if docker image inspect "$NEW_IMAGE" >/dev/null 2>&1; then
    note "$NEW_IMAGE is already loaded"
else
    if [[ -z "$IMAGE_TAR" ]]; then
        for candidate in "$BUNDLE_DIR/.." "$INSTALL_ROOT" /tmp; do
            for name in "masp-pilot-$NEW_VERSION-image.tar" "masp-pilot-$NEW_VERSION-images.tar"; do
                if [[ -z "$IMAGE_TAR" && -f "$candidate/$name" ]]; then
                    IMAGE_TAR="$(cd "$candidate" && pwd)/$name"
                fi
            done
        done
    fi
    [[ -n "$IMAGE_TAR" && -f "$IMAGE_TAR" ]] || \
        die "$NEW_IMAGE is not loaded and no masp-pilot-$NEW_VERSION-image.tar was found; pass --image FILE"
    [[ -f "$IMAGE_TAR.sha256" ]] || die "missing checksum file: $IMAGE_TAR.sha256"
    (cd "$(dirname "$IMAGE_TAR")" && sha256sum -c --quiet "$(basename "$IMAGE_TAR").sha256" >/dev/null 2>&1) || \
        die "checksum mismatch: $(basename "$IMAGE_TAR"). Copy it again."
    if [[ $DRY_RUN -eq 1 ]]; then
        note "Would load $IMAGE_TAR"
    else
        note "Loading $(basename "$IMAGE_TAR") (a few minutes)"
        docker load -i "$IMAGE_TAR" >/dev/null
        docker image inspect "$NEW_IMAGE" >/dev/null 2>&1 || die "$(basename "$IMAGE_TAR") does not contain $NEW_IMAGE"
        note "Loaded $NEW_IMAGE; the old image stays for a rollback"
    fi
fi

# ---------------------------------------------------------------------------
step "Configuration"
NEW_ENV="$BUNDLE_DIR/.env.pilot"
if [[ -f "$NEW_ENV" ]]; then
    # A rerun after a later step failed: the carried file was already prepared.
    note "Keeping the existing $NEW_ENV (prepared by an earlier run; delete it to carry $FROM/.env.pilot again)"
    candidate_env="$NEW_ENV"
else
    candidate_env="$(mktemp "$BUNDLE_DIR/.env.pilot.XXXXXX")"
    chmod 600 "$candidate_env"
    cp "$FROM/.env.pilot" "$candidate_env"
    added=()
    while IFS= read -r line; do
        key="${line%%=*}"
        if ! has_key "$key" "$candidate_env"; then
            [[ ${#added[@]} -gt 0 ]] || printf '\n# --- added from .env.pilot.example by upgrade.sh for %s ---\n' "$NEW_VERSION" >> "$candidate_env"
            printf '%s\n' "$line" >> "$candidate_env"
            added+=("$key")
        fi
    done < <(grep -E '^[A-Z][A-Z0-9_]*=' "$BUNDLE_DIR/.env.pilot.example")
    note "Kept every existing value; ${#added[@]} new setting(s) added with the example's defaults (--dry-run lists them)"

    set_env MASP_IMAGE "$NEW_IMAGE" "$candidate_env"
    note "MASP_IMAGE=$NEW_IMAGE"

    # Older releases kept YARA rules inside the release directory (./rules), which
    # the new directory would replace with the bundled defaults.
    rules="$(env_value MASP_RULES_DIR "$candidate_env")"
    if [[ -n "$rules" && "$rules" != /* ]]; then
        old_rules="$FROM/$rules"
        target="$DATA_ROOT/rules"
        if [[ -d "$target" && -n "$(ls -A "$target" 2>/dev/null)" ]]; then
            die "MASP_RULES_DIR is $rules inside the old release, and $target already has files. Merge the rules into $target by hand, set MASP_RULES_DIR=$target in $FROM/.env.pilot and rerun"
        fi
        if [[ $DRY_RUN -eq 1 ]]; then
            note "Would copy the rules from $old_rules to $target"
            # Validated below against the rules as they are now; the copy does not exist yet.
            DRY_RUN_RULES="$old_rules"
        else
            mkdir -p "$target"
            cp -a "$old_rules/." "$target/"
            note "Copied the YARA rules from $old_rules to $target"
        fi
        set_env MASP_RULES_DIR "$target" "$candidate_env"
    fi

    # The example's placeholders are public values; install.sh refuses them.
    if [[ "$(env_value MASP_WORKER_ENROLLMENT_TOKEN "$candidate_env")" == CHANGE_ME* ]]; then
        set_env MASP_WORKER_ENROLLMENT_TOKEN "" "$candidate_env"
        note "MASP_WORKER_ENROLLMENT_TOKEN emptied (placeholder); enrolled workers keep working"
    fi
    if [[ "$(env_value MASP_SECRET_ENCRYPTION_KEY "$candidate_env")" == CHANGE_ME* ]]; then
        command -v openssl >/dev/null || die "openssl is needed to generate MASP_SECRET_ENCRYPTION_KEY"
        set_env MASP_SECRET_ENCRYPTION_KEY "$(openssl rand 32 | base64 | tr '+/' '-_')" "$candidate_env"
        note "MASP_SECRET_ENCRYPTION_KEY generated (was a placeholder)"
    fi

    # An explicit worker engine list must name the built-in engines to run them.
    engines="$(env_value MASP_WORKER_ENGINE_KEYS "$candidate_env")"
    if [[ -n "$engines" ]]; then
        for engine in file_type hash_list; do
            if [[ ",$engines," != *",$engine,"* ]]; then
                engines="$engines,$engine"
                note "MASP_WORKER_ENGINE_KEYS: added $engine"
            fi
        done
        set_env MASP_WORKER_ENGINE_KEYS "$engines" "$candidate_env"
    fi

    # Settings a release before the browser console did not have. Behind nginx the
    # app must trust its forwarded headers; over plain HTTP the session cookie
    # must not be marked Secure, or every sign-in loops back to the login page.
    if [[ " ${added[*]:-} " == *" MASP_FORWARDED_ALLOW_IPS "* || " ${added[*]:-} " == *" MASP_SESSION_SECURE "* ]]; then
        if proxy_in_front; then
            gateway="$(docker network inspect "${PROJECT}_default" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)"
            [[ -n "$gateway" ]] || die "nginx is running but the ${PROJECT}_default network has no gateway; set MASP_FORWARDED_ALLOW_IPS by hand"
            set_env MASP_FORWARDED_ALLOW_IPS "$gateway" "$candidate_env"
            set_env MASP_SESSION_SECURE 1 "$candidate_env"
            note "nginx in front: forwarded headers trusted from $gateway, Secure session cookie"
        else
            set_env MASP_FORWARDED_ALLOW_IPS 127.0.0.1 "$candidate_env"
            set_env MASP_SESSION_SECURE "" "$candidate_env"
            note "No nginx: plain HTTP console, session cookie not marked Secure"
        fi
    fi

    left="$(grep -E '^[A-Z][A-Z0-9_]*=CHANGE_ME' "$candidate_env" | cut -d= -f1 | tr '\n' ' ' || true)"
    if [[ -n "$left" ]]; then
        rm -f "$candidate_env"
        die "placeholders left in the configuration: $left. Set real values in $FROM/.env.pilot and rerun"
    fi
    if [[ -f "$FROM/clamav.env" && ! -f "$BUNDLE_DIR/clamav.env" ]]; then
        if [[ $DRY_RUN -eq 1 ]]; then
            note "Would carry clamav.env over"
        else
            cp -a "$FROM/clamav.env" "$BUNDLE_DIR/clamav.env"
            note "clamav.env carried over"
        fi
    fi
fi

# Validate before anything running is touched.
validate_env="$candidate_env"
if [[ -n "${DRY_RUN_RULES:-}" ]]; then
    validate_env="$(mktemp "$BUNDLE_DIR/.env.pilot.XXXXXX")"
    cp "$candidate_env" "$validate_env"
    set_env MASP_RULES_DIR "$DRY_RUN_RULES" "$validate_env"
fi
if ! (cd "$BUNDLE_DIR" && bash ./deploy/pilot/install.sh --env-file "$validate_env" --no-build --dry-run >/dev/null); then
    [[ "$validate_env" == "$candidate_env" ]] || rm -f "$validate_env"
    [[ "$candidate_env" == "$NEW_ENV" ]] || rm -f "$candidate_env"
    die "the carried configuration does not validate; the message above names the setting"
fi
[[ "$validate_env" == "$candidate_env" ]] || rm -f "$validate_env"
compose=(docker compose -p "$PROJECT" -f "$BUNDLE_DIR/docker-compose.pilot.yml" --env-file "$candidate_env")
images="$("${compose[@]}" config --images 2>/dev/null | tr -d '\r' | sort -u || true)"
if [[ -z "$images" ]]; then
    # An older Compose without --images: check what the settings name.
    images="$(printf '%s\n' "$NEW_IMAGE" "$(env_value MASP_POSTGRES_IMAGE "$candidate_env")" "$(env_value MASP_CLAMAV_IMAGE "$candidate_env")")"
fi
while IFS= read -r image; do
    [[ -n "$image" ]] || continue
    if ! docker image inspect "$image" >/dev/null 2>&1; then
        if [[ $DRY_RUN -eq 1 && "$image" == "$NEW_IMAGE" ]]; then continue; fi
        [[ "$candidate_env" == "$NEW_ENV" ]] || rm -f "$candidate_env"
        die "image $image is not on this host and cannot be pulled offline; carry it with docker save"
    fi
done <<< "$images"
note "Configuration validates; every image it names is on this host"

if [[ $DRY_RUN -eq 1 ]]; then
    printf '\nChanges to the carried settings (secrets are not shown):\n'
    diff <(masked "$FROM/.env.pilot") <(masked "$candidate_env") | grep '^[<>]' || true
    [[ "$candidate_env" == "$NEW_ENV" ]] || rm -f "$candidate_env"
    printf '\nDry run: nothing was changed. Without --dry-run the next steps back up, install and verify.\n'
    exit 0
fi
if [[ "$candidate_env" != "$NEW_ENV" ]]; then
    mv "$candidate_env" "$NEW_ENV"
    chmod 600 "$NEW_ENV"
    note "Wrote $NEW_ENV"
fi

if [[ $ASSUME_YES -eq 0 ]]; then
    printf '\nUpgrade %s -> %s. The services stop briefly for the backup and again for the switch.\n' "$OLD_VERSION" "$NEW_VERSION"
    read -r -p "Continue? [y/N] " answer </dev/tty || true
    [[ "$answer" == [yY]* ]] || { echo "Stopped; nothing running was changed."; exit 1; }
fi

# ---------------------------------------------------------------------------
step "Backup with $OLD_VERSION's own backup.sh"
mkdir -p "$BACKUP_ROOT"
before="$(ls -d "$BACKUP_ROOT"/masp-pilot-* 2>/dev/null | sort || true)"
(cd "$FROM" && bash ./deploy/pilot/backup.sh --env-file .env.pilot --output-dir "$BACKUP_ROOT") || \
    die "the backup failed; nothing was upgraded"
created="$(comm -13 <(printf '%s\n' "$before") <(ls -d "$BACKUP_ROOT"/masp-pilot-* 2>/dev/null | sort) | tail -n 1)"
[[ -n "$created" && -d "$created" ]] || die "backup.sh finished but no new backup directory appeared in $BACKUP_ROOT"
if [[ -f "$created/SHA256SUMS" ]]; then
    (cd "$created" && sha256sum -c --quiet SHA256SUMS >/dev/null 2>&1) || die "the backup in $created does not match its checksums; nothing was upgraded"
fi
BACKUP_DIR="$created"
note "Backup: $BACKUP_DIR (checksums OK)"

# ---------------------------------------------------------------------------
step "Installing $NEW_VERSION"
chmod +x "$BUNDLE_DIR"/deploy/pilot/*.sh
# tools/ is mounted into the containers, which run as an unprivileged user.
chmod -R go+rX "$BUNDLE_DIR/tools"
(cd "$BUNDLE_DIR" && ./deploy/pilot/install.sh --env-file .env.pilot --no-build) || \
    die "install.sh failed; see the messages above"

# ---------------------------------------------------------------------------
step "Switching $INSTALL_ROOT/current and the masp command"
mkdir -p "$INSTALL_ROOT" "$(dirname "$WRAPPER")"
ln -sfn "$BUNDLE_DIR" "$INSTALL_ROOT/current"
printf '#!/usr/bin/env bash\ncd %s/current && exec docker compose -p %s -f docker-compose.pilot.yml --env-file .env.pilot "$@"\n' \
    "$INSTALL_ROOT" "$PROJECT" > "$WRAPPER"
chmod +x "$WRAPPER"
note "$INSTALL_ROOT/current -> $BUNDLE_DIR"

# ---------------------------------------------------------------------------
step "Acceptance checks"
(cd "$BUNDLE_DIR" && ./deploy/pilot/verify.sh --env-file .env.pilot) || \
    die "the new release fails its acceptance checks"

# ---------------------------------------------------------------------------
step "Done"
printf '\n===== MASP upgraded %s -> %s =====\n' "$OLD_VERSION" "$NEW_VERSION"
printf '  Backup:   %s\n' "$BACKUP_DIR"
printf '  Old copy: %s (unchanged; keep it and its image until you are sure)\n' "$FROM"
printf '  Log:      %s\n' "$LOG_FILE"
printf '  Rollback, only if needed:\n'
printf '    cd %q && ./deploy/pilot/install.sh --env-file .env.pilot --no-build && ./deploy/pilot/restore.sh --env-file .env.pilot --backup-dir %q --yes && ln -sfn %q %q/current\n' \
    "$FROM" "$BACKUP_DIR" "$FROM" "$INSTALL_ROOT"
