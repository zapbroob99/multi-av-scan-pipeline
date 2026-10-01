#!/usr/bin/env bash
# First installation of the MASP pilot on an Ubuntu 22.04 or 24.04 host with no internet
# access. Everything comes from a media directory carried to the host:
#
#   masp-docker-offline-<codename>-amd64.tar  Docker Engine and Compose packages
#   masp-tools-offline-<codename>-amd64.tar   nginx, cifs-utils, unzip
#   masp-pilot-<version>-images.tar       MASP, PostgreSQL and ClamAV images
#   clamav-signatures-<date>.tar          current ClamAV databases
#   and a .sha256 file beside each of them.
#
# Run it from the extracted release bundle. It is safe to run again: finished
# steps are skipped, and an existing .env.pilot is kept as it is. Every step
# stops the run with a reason when it fails; nothing is half applied silently.
#
# Usage: deploy/pilot/offline_install.sh --media DIR [--server-name NAME]
#          [--server-ip IP] [--icap-clients IP[,IP...]|none] [--docker-pool CIDR]
#          [--cert FILE --key FILE] [--clamav-mirror URL] [--yes]
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
BUNDLE_DIR="$(cd "$SCRIPT_DIR/../.." && pwd)"
LOG_FILE="${MASP_INSTALL_LOG:-/var/log/masp-offline-install.log}"
PROJECT="${MASP_PILOT_PROJECT:-masp-pilot}"
CREDENTIALS_FILE=/root/masp-install-credentials.txt
DATA_ROOT=/srv/masp
SSL_DIR=/etc/ssl/masp

MEDIA=""
SERVER_NAME=""
SERVER_IP=""
ICAP_CLIENTS=""
DOCKER_POOL=""
CERT_FILE=""
KEY_FILE=""
CLAMAV_MIRROR=""
ASSUME_YES=0

usage() {
    sed -n '2,18p' "$0" | sed 's/^# \{0,1\}//'
}

die() {
    printf '\nERROR: %s\n' "$*" >&2
    printf 'The full log is in %s. Fix the cause and run the same command again.\n' "$LOG_FILE" >&2
    exit 1
}

STEP=0
step() {
    STEP=$((STEP + 1))
    printf '\n==> [%s/12] %s\n' "$STEP" "$*"
}

note() {
    printf '    %s\n' "$*"
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --media) MEDIA="${2:-}"; shift 2 ;;
        --server-name) SERVER_NAME="${2:-}"; shift 2 ;;
        --server-ip) SERVER_IP="${2:-}"; shift 2 ;;
        --icap-clients) ICAP_CLIENTS="${2:-}"; shift 2 ;;
        --docker-pool) DOCKER_POOL="${2:-}"; shift 2 ;;
        --cert) CERT_FILE="${2:-}"; shift 2 ;;
        --key) KEY_FILE="${2:-}"; shift 2 ;;
        --clamav-mirror) CLAMAV_MIRROR="${2:-}"; shift 2 ;;
        --yes) ASSUME_YES=1; shift ;;
        -h|--help) usage; exit 0 ;;
        *) printf 'unknown argument: %s\n' "$1" >&2; usage >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "Run as root (sudo -i first)." >&2; exit 1; }
mkdir -p "$(dirname "$LOG_FILE")"
exec > >(tee -a "$LOG_FILE") 2>&1
# Files this script creates for nginx, docker and the containers must be
# world-readable; secrets get their own stricter modes below.
umask 022
printf '\n===== MASP offline install %s =====\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)"

has_systemd() { [[ -d /run/systemd/system ]]; }
valid_ip() { [[ "$1" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; }

ask() {
    # ask VARIABLE "question" "default"
    local name="$1" question="$2" default="${3:-}" answer
    if [[ -n "${!name}" ]]; then return; fi
    if [[ $ASSUME_YES -eq 1 ]]; then
        printf -v "$name" '%s' "$default"
        return
    fi
    read -r -p "$question [${default}]: " answer </dev/tty || true
    printf -v "$name" '%s' "${answer:-$default}"
}

set_env() {
    local key="$1" value="$2" file="$3"
    if grep -q "^${key}=" "$file"; then
        # The value never contains '|': generated tokens are alphanumeric.
        sed -i "s|^${key}=.*|${key}=${value}|" "$file"
    else
        printf '%s=%s\n' "$key" "$value" >> "$file"
    fi
}

env_value() {
    sed -n "s/^$1=//p" "$2" | tail -n 1
}

random_token() {
    # Alphanumeric only, so it passes every validator and needs no quoting.
    local token=""
    while [[ ${#token} -lt $1 ]]; do
        token+="$(openssl rand -base64 64 | tr -dc 'A-Za-z0-9')"
    done
    printf '%s' "${token:0:$1}"
}

package_installed() {
    [[ "$(dpkg-query -W -f='${Status}' "$1" 2>/dev/null)" == "install ok installed" ]]
}

install_from_local_repo() {
    # install_from_local_repo ARCHIVE DIRECTORY PACKAGE...
    # The archive holds a flat apt repository. apt installs only what is missing
    # and never downgrades a package the host already has.
    local archive="$1" directory="$2" list
    shift 2
    rm -rf "/opt/$directory"
    tar -xf "$archive" -C /opt
    [[ -f "/opt/$directory/Packages" ]] || die "$(basename "$archive") is not an apt repository"
    list="/etc/apt/sources.list.d/masp-$directory.list"
    echo "deb [trusted=yes] file:/opt/$directory ./" > "$list"
    local apt_options=(-o "Dir::Etc::sourcelist=$list" -o "Dir::Etc::sourceparts=-" -o "APT::Get::List-Cleanup=0")
    apt-get "${apt_options[@]}" update -qq || { rm -f "$list"; die "apt could not read $(basename "$archive")"; }
    # Completes an interrupted earlier attempt; a no-op on a healthy system.
    DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install -y -qq -f --no-install-recommends >/dev/null || true
    local output
    output="$(mktemp)"
    if ! DEBIAN_FRONTEND=noninteractive apt-get "${apt_options[@]}" install -y -qq --no-install-recommends "$@" >"$output" 2>&1; then
        rm -f "$list"
        tail -n 25 "$output"
        rm -f "$output"
        die "apt could not install $* from $(basename "$archive"); the lines above give apt's reason"
    fi
    rm -f "$output"
    rm -f "$list"
}

wait_for_docker() {
    local i
    for i in $(seq 1 60); do
        docker info >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

# ---------------------------------------------------------------------------
step "Checking the host and the carried files"
[[ -f "$BUNDLE_DIR/RELEASE.json" && -f "$BUNDLE_DIR/docker-compose.pilot.yml" ]] || \
    die "run this script from an extracted release bundle"
RELEASE_VERSION="$(sed -n 's/.*"version": *"\([^"]*\)".*/\1/p' "$BUNDLE_DIR/RELEASE.json")"
[[ -n "$RELEASE_VERSION" ]] || die "cannot read the release version from RELEASE.json"
note "Release: $RELEASE_VERSION ($BUNDLE_DIR)"

# Read in a subshell: os-release defines VERSION, NAME and ID of its own.
os_id="$(. /etc/os-release && printf '%s' "${ID:-}")"
os_version="$(. /etc/os-release && printf '%s' "${VERSION_ID:-}")"
os_name="$(. /etc/os-release && printf '%s' "${PRETTY_NAME:-unknown}")"
case "$os_id/$os_version/$(uname -m)" in
    ubuntu/22.04/x86_64) CODENAME=jammy ;;
    ubuntu/24.04/x86_64) CODENAME=noble ;;
    *) die "the offline packages are for Ubuntu 22.04 or 24.04 x86_64; this host is $os_name $(uname -m)" ;;
esac
note "Host: $os_name (packages: $CODENAME)"
for command in sha256sum tar openssl dpkg apt-get sed awk; do
    command -v "$command" >/dev/null || die "required command missing: $command"
done

[[ -n "$MEDIA" ]] || die "pass --media with the directory that holds the carried files"
[[ -d "$MEDIA" ]] || die "media directory not found: $MEDIA"
MEDIA="$(cd "$MEDIA" && pwd)"
DOCKER_TAR="$MEDIA/masp-docker-offline-$CODENAME-amd64.tar"
TOOLS_TAR="$MEDIA/masp-tools-offline-$CODENAME-amd64.tar"
IMAGES_TAR="$MEDIA/masp-pilot-$RELEASE_VERSION-images.tar"
SIGNATURE_TAR="$(find "$MEDIA" -maxdepth 1 -name 'clamav-signatures-*.tar' | sort | tail -n 1)"
for file in "$DOCKER_TAR" "$TOOLS_TAR" "$IMAGES_TAR" "$SIGNATURE_TAR"; do
    [[ -n "$file" && -f "$file" ]] || die "missing carried file: ${file:-clamav-signatures-<date>.tar} (see the guide's file list)"
    [[ -f "$file.sha256" ]] || die "missing checksum file: $file.sha256"
    (cd "$MEDIA" && sha256sum -c --quiet "$(basename "$file").sha256") || \
        die "checksum mismatch: $(basename "$file"). Copy it again."
    note "OK $(basename "$file")"
done

ask SERVER_NAME "DNS name users will open the console with" "$(hostname -f 2>/dev/null || hostname)"
ask SERVER_IP "This server's IP address on the internal network" "$(hostname -I 2>/dev/null | awk '{print $1}')"
ask ICAP_CLIENTS "ICAP client IP addresses, comma separated (none if ICAP is not used)" "none"
valid_ip "$SERVER_IP" || die "not an IPv4 address: $SERVER_IP"
[[ "$SERVER_NAME" =~ ^[A-Za-z0-9.-]+$ ]] || die "not a host name: $SERVER_NAME"
ICAP_CLIENTS="${ICAP_CLIENTS// /}"
[[ "$ICAP_CLIENTS" == "none" ]] && ICAP_CLIENTS=""
if [[ -n "$ICAP_CLIENTS" ]]; then
    IFS=',' read -r -a ICAP_LIST <<< "$ICAP_CLIENTS"
    for address in "${ICAP_LIST[@]}"; do
        valid_ip "$address" || die "not an IPv4 address in --icap-clients: $address (CIDR ranges are not supported)"
    done
else
    ICAP_LIST=()
fi
if [[ -n "$CERT_FILE" || -n "$KEY_FILE" ]]; then
    [[ -f "$CERT_FILE" && -f "$KEY_FILE" ]] || die "--cert and --key must both name existing files"
fi
note "Server: $SERVER_NAME ($SERVER_IP); ICAP clients: ${ICAP_CLIENTS:-none}"

# ---------------------------------------------------------------------------
step "Docker Engine"
if package_installed docker-ce && package_installed docker-compose-plugin; then
    note "Already installed: $(docker --version)"
else
    # Also repairs a half-configured earlier attempt: apt adds what was missing.
    install_from_local_repo "$DOCKER_TAR" docker-offline docker-ce docker-ce-cli containerd.io \
        docker-buildx-plugin docker-compose-plugin docker-ce-rootless-extras
    note "Installed: $(docker --version)"
fi
restart_docker=0
if [[ -n "$DOCKER_POOL" ]]; then
    wanted="{\"default-address-pools\": [{\"base\": \"$DOCKER_POOL\", \"size\": 24}]}"
    if [[ ! -f /etc/docker/daemon.json ]]; then
        mkdir -p /etc/docker
        printf '%s\n' "$wanted" > /etc/docker/daemon.json
        restart_docker=1
        note "Docker networks will use $DOCKER_POOL"
    elif ! grep -q "$DOCKER_POOL" /etc/docker/daemon.json; then
        die "/etc/docker/daemon.json exists without $DOCKER_POOL; merge it by hand, then rerun"
    fi
fi
if has_systemd; then
    systemctl enable --now docker >/dev/null
    [[ $restart_docker -eq 0 ]] || systemctl restart docker
elif ! docker info >/dev/null 2>&1; then
    # Only for rehearsals in a container without systemd; a real server has it.
    nohup dockerd > /var/log/dockerd.log 2>&1 &
fi
wait_for_docker || die "Docker did not start; see 'journalctl -u docker'"
docker compose version >/dev/null 2>&1 || die "the Docker Compose plugin is missing"
note "$(docker compose version)"

# ---------------------------------------------------------------------------
step "nginx, cifs-utils and unzip"
missing=()
for package in nginx cifs-utils unzip; do
    package_installed "$package" || missing+=("$package")
done
if [[ ${#missing[@]} -eq 0 ]]; then
    note "Already installed"
else
    # Do not let the package start nginx: its default site also listens on [::]:80
    # and fails on hosts with IPv6 disabled, which fails the whole installation.
    # Our own site (step 10) listens on IPv4 only and replaces the default.
    created_policy=0
    if [[ ! -e /usr/sbin/policy-rc.d ]]; then
        printf '#!/bin/sh\nexit 101\n' > /usr/sbin/policy-rc.d
        chmod 755 /usr/sbin/policy-rc.d
        created_policy=1
    fi
    rm -f /etc/nginx/sites-enabled/default
    install_from_local_repo "$TOOLS_TAR" tools-offline "${missing[@]}"
    rm -f /etc/nginx/sites-enabled/default
    [[ $created_policy -eq 0 ]] || rm -f /usr/sbin/policy-rc.d
    note "Installed: ${missing[*]}"
fi

# ---------------------------------------------------------------------------
step "Container images"
images=("masp-pilot:$RELEASE_VERSION" "postgres:16-alpine" "clamav/clamav:stable")
need_load=0
for image in "${images[@]}"; do
    docker image inspect "$image" >/dev/null 2>&1 || need_load=1
done
if [[ $need_load -eq 1 ]]; then
    note "Loading $(basename "$IMAGES_TAR") (a few minutes)"
    docker load -i "$IMAGES_TAR" >/dev/null
fi
for image in "${images[@]}"; do
    docker image inspect "$image" >/dev/null 2>&1 || die "image not available after loading: $image"
    note "OK $image"
done

# ---------------------------------------------------------------------------
step "Directories and the masp command"
# /usr/local/bin and /usr/local/sbin are absent on some hardened images.
mkdir -p "$DATA_ROOT/storage" "$DATA_ROOT/rules" "$DATA_ROOT/backups" /opt/masp /usr/local/bin /usr/local/sbin
if [[ -z "$(ls -A "$DATA_ROOT/rules")" ]]; then
    cp -a "$BUNDLE_DIR/rules/." "$DATA_ROOT/rules/"
    note "Copied the bundled YARA rules to $DATA_ROOT/rules"
fi
chmod +x "$BUNDLE_DIR"/deploy/pilot/*.sh
# Hardened hosts often run root with umask 027 or 077, so the extracted bundle
# is readable by root alone. tools/ is mounted into the containers, which run
# as an unprivileged user; .env.pilot stays root-only (install.sh sets 600).
chmod -R go+rX "$BUNDLE_DIR/tools"
ln -sfn "$BUNDLE_DIR" /opt/masp/current
printf '#!/usr/bin/env bash\ncd /opt/masp/current && exec docker compose -p %s -f docker-compose.pilot.yml --env-file .env.pilot "$@"\n' \
    "$PROJECT" > /usr/local/bin/masp
chmod +x /usr/local/bin/masp
note "/opt/masp/current -> $BUNDLE_DIR; 'masp ps' and 'masp logs' are available"

# ---------------------------------------------------------------------------
step "Configuration (.env.pilot and clamav.env)"
ENV_FILE="$BUNDLE_DIR/.env.pilot"
if [[ -f "$ENV_FILE" ]]; then
    note "Keeping the existing $ENV_FILE; the answers above are not applied to it"
else
    tmp_env="$(mktemp "$BUNDLE_DIR/.env.pilot.XXXXXX")"
    cp "$BUNDLE_DIR/.env.pilot.example" "$tmp_env"
    chmod 600 "$tmp_env"
    admin_password="$(random_token 20)"
    api_token="$(random_token 48)"
    set_env MASP_IMAGE "masp-pilot:$RELEASE_VERSION" "$tmp_env"
    # Loaded images carry tags, not registry digests.
    set_env MASP_POSTGRES_IMAGE postgres:16-alpine "$tmp_env"
    set_env MASP_CLAMAV_IMAGE clamav/clamav:stable "$tmp_env"
    set_env MASP_POSTGRES_PASSWORD "$(random_token 40)" "$tmp_env"
    set_env MASP_API_TOKEN "$api_token" "$tmp_env"
    set_env MASP_ADMIN_PASSWORD "$admin_password" "$tmp_env"
    set_env MASP_SECRET_ENCRYPTION_KEY "$(openssl rand 32 | base64 | tr '+/' '-_')" "$tmp_env"
    set_env MASP_WORKER_ENROLLMENT_TOKEN "" "$tmp_env"
    set_env MASP_STORAGE_DIR "$DATA_ROOT/storage" "$tmp_env"
    set_env MASP_RULES_DIR "$DATA_ROOT/rules" "$tmp_env"
    # VirusTotal needs the internet.
    set_env MASP_WORKER_ENGINE_KEYS static_metadata,file_type,hash_list,clamav,yara "$tmp_env"
    set_env MASP_VIRUSTOTAL_ENABLED 0 "$tmp_env"
    set_env MASP_APP_BIND 127.0.0.1:8000 "$tmp_env"
    set_env MASP_SESSION_SECURE 1 "$tmp_env"
    # Narrowed to the Docker gateway once the network exists (step 9).
    set_env MASP_FORWARDED_ALLOW_IPS "${DOCKER_POOL:-172.16.0.0/12}" "$tmp_env"
    if [[ ${#ICAP_LIST[@]} -gt 0 ]]; then
        set_env MASP_ICAP_BIND "$SERVER_IP:1344" "$tmp_env"
        set_env MASP_ICAP_ALLOWED_IPS "127.0.0.1,$ICAP_CLIENTS" "$tmp_env"
    else
        set_env MASP_ICAP_BIND 127.0.0.1:1344 "$tmp_env"
        set_env MASP_ICAP_ALLOWED_IPS 127.0.0.1 "$tmp_env"
    fi
    if grep -q '^[^#]*CHANGE_ME' "$tmp_env"; then
        rm -f "$tmp_env"
        die "a placeholder is left in the generated configuration; report this"
    fi
    mv "$tmp_env" "$ENV_FILE"
    (umask 077; {
        printf 'MASP installation %s on %s\n\n' "$RELEASE_VERSION" "$(date -u +%Y-%m-%d)"
        printf 'Console:        https://%s/console/\n' "$SERVER_NAME"
        printf 'Console user:   admin\n'
        printf 'Admin password: %s   (change it after the first sign-in)\n' "$admin_password"
        printf 'API token:      %s   (compatibility token; prefer per-client credentials)\n' "$api_token"
        [[ ${#ICAP_LIST[@]} -eq 0 ]] || printf 'ICAP service:   icap://%s:1344/masp\n' "$SERVER_IP"
    } > "$CREDENTIALS_FILE")
    chmod 600 "$CREDENTIALS_FILE"
    note "Generated $ENV_FILE; secrets written to $CREDENTIALS_FILE (root only)"
fi
if [[ ! -f "$BUNDLE_DIR/clamav.env" ]]; then
    if [[ -n "$CLAMAV_MIRROR" ]]; then
        printf 'FRESHCLAM_CONF_PrivateMirror=%s\nFRESHCLAM_CHECKS=12\n' "$CLAMAV_MIRROR" > "$BUNDLE_DIR/clamav.env"
        note "ClamAV updates from $CLAMAV_MIRROR"
    else
        # No update path: freshclam would retry and log errors all day.
        printf 'CLAMAV_NO_FRESHCLAMD=true\n' > "$BUNDLE_DIR/clamav.env"
        note "ClamAV signatures are loaded by hand (no mirror given)"
    fi
fi

# ---------------------------------------------------------------------------
step "ClamAV signatures"
signature_root=/var/tmp/masp-clamav-signatures
rm -rf "$signature_root"
mkdir -p "$signature_root"
tar -xf "$SIGNATURE_TAR" -C "$signature_root"
signature_dir="$(find "$signature_root" -mindepth 1 -maxdepth 1 -type d | head -n 1)"
[[ -n "$signature_dir" ]] || die "the signature archive holds no directory"
"$BUNDLE_DIR/deploy/pilot/load_clamav_signatures.sh" --env-file "$ENV_FILE" "$signature_dir"
rm -rf "$signature_root"

# ---------------------------------------------------------------------------
step "Starting MASP"
cd "$BUNDLE_DIR"
./deploy/pilot/install.sh --env-file "$ENV_FILE" --no-build --dry-run >/dev/null || \
    die "the configuration did not validate; see the message above"
./deploy/pilot/install.sh --env-file "$ENV_FILE" --no-build

# ---------------------------------------------------------------------------
step "Trusting only the local proxy"
gateway="$(docker network inspect "${PROJECT}_default" --format '{{range .IPAM.Config}}{{.Gateway}}{{end}}' 2>/dev/null || true)"
current="$(env_value MASP_FORWARDED_ALLOW_IPS "$ENV_FILE")"
if [[ -n "$gateway" && "$current" != "$gateway" ]]; then
    set_env MASP_FORWARDED_ALLOW_IPS "$gateway" "$ENV_FILE"
    ./deploy/pilot/install.sh --env-file "$ENV_FILE" --no-build >/dev/null
    note "Forwarded headers are trusted only from $gateway (nginx on this host)"
else
    note "Already set to ${current}"
fi

# ---------------------------------------------------------------------------
step "HTTPS with nginx"
mkdir -p "$SSL_DIR"
chmod 700 "$SSL_DIR"
if [[ -n "$CERT_FILE" ]]; then
    install -m 600 "$KEY_FILE" "$SSL_DIR/masp.key"
    install -m 644 "$CERT_FILE" "$SSL_DIR/masp.crt"
    note "Using the supplied certificate"
elif [[ ! -f "$SSL_DIR/masp.key" ]]; then
    openssl req -new -newkey rsa:3072 -nodes -keyout "$SSL_DIR/masp.key" -out "$SSL_DIR/masp.csr" \
        -subj "/CN=$SERVER_NAME" -addext "subjectAltName=DNS:$SERVER_NAME,IP:$SERVER_IP" 2>/dev/null
    # A temporary self-signed certificate from the same key, so the console works
    # at once; replace it with the institution certificate for this CSR.
    openssl x509 -req -in "$SSL_DIR/masp.csr" -signkey "$SSL_DIR/masp.key" -days 365 \
        -copy_extensions copy -out "$SSL_DIR/masp.crt" 2>/dev/null
    chmod 600 "$SSL_DIR/masp.key"
    note "Temporary self-signed certificate; send $SSL_DIR/masp.csr to the PKI team"
else
    note "Keeping the existing certificate in $SSL_DIR"
fi
cat > /etc/nginx/sites-available/masp <<EOF
server {
    listen 80;
    server_name $SERVER_NAME $SERVER_IP;
    return 301 https://\$host\$request_uri;
}

server {
    listen 443 ssl;
    server_name $SERVER_NAME $SERVER_IP;

    ssl_certificate     $SSL_DIR/masp.crt;
    ssl_certificate_key $SSL_DIR/masp.key;
    ssl_protocols TLSv1.2 TLSv1.3;

    # The browser API is limited to 128 KiB; only upload routes need more.
    client_max_body_size 1m;

    # MASP's same-origin and HTTPS checks rely on these headers.
    proxy_set_header Host              \$http_host;
    proxy_set_header X-Forwarded-Proto https;
    proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
    proxy_read_timeout 120s;

    location = /api/v1/scans    { client_max_body_size 64m; proxy_pass http://127.0.0.1:8000; }
    location = /api/ui/v1/scans { client_max_body_size 64m; proxy_pass http://127.0.0.1:8000; }
    location / { proxy_pass http://127.0.0.1:8000; }
}
EOF
ln -sfn /etc/nginx/sites-available/masp /etc/nginx/sites-enabled/masp
rm -f /etc/nginx/sites-enabled/default
nginx -t 2>/dev/null || { nginx -t; die "nginx rejected the configuration"; }
if has_systemd; then
    systemctl enable --now nginx >/dev/null
    systemctl reload nginx
elif [[ -s /run/nginx.pid ]] && kill -0 "$(cat /run/nginx.pid)" 2>/dev/null; then
    nginx -s reload
else
    nginx
fi
for attempt in $(seq 1 30); do
    curl -skf "https://127.0.0.1/health" -H "Host: $SERVER_NAME" >/dev/null 2>&1 && break
    sleep 1
done
curl -skf "https://127.0.0.1/health" -H "Host: $SERVER_NAME" >/dev/null || die "MASP does not answer through nginx"
note "https://$SERVER_NAME/console/ answers"

# ---------------------------------------------------------------------------
step "ICAP port restriction"
if [[ ${#ICAP_LIST[@]} -eq 0 ]]; then
    note "ICAP listens on 127.0.0.1 only; nothing to open"
else
    interface="$(ip route get "${ICAP_LIST[0]}" 2>/dev/null | awk '{for (i = 1; i < NF; i++) if ($i == "dev") print $(i + 1)}' | head -n 1)"
    [[ -n "$interface" ]] || die "cannot find the network interface towards ${ICAP_LIST[0]}"
    {
        printf '#!/usr/bin/env bash\n'
        printf '# ICAP (1344) only from the approved clients. Docker-published ports bypass\n'
        printf '# UFW, so the restriction lives in the DOCKER-USER chain. Written by\n'
        printf '# offline_install.sh; rerun it after changing the client list.\n'
        printf 'set -e\nIF=%s\n' "$interface"
        printf 'while iptables -D DOCKER-USER -i "$IF" -p tcp --dport 1344 -j DROP 2>/dev/null; do :; done\n'
        for address in "${ICAP_LIST[@]}"; do
            printf 'while iptables -D DOCKER-USER -i "$IF" -p tcp --dport 1344 -s %s -j ACCEPT 2>/dev/null; do :; done\n' "$address"
        done
        printf 'iptables -I DOCKER-USER -i "$IF" -p tcp --dport 1344 -j DROP\n'
        for address in "${ICAP_LIST[@]}"; do
            printf 'iptables -I DOCKER-USER -i "$IF" -p tcp --dport 1344 -s %s -j ACCEPT\n' "$address"
        done
    } > /usr/local/sbin/masp-firewall.sh
    chmod 700 /usr/local/sbin/masp-firewall.sh
    if has_systemd; then
        cat > /etc/systemd/system/masp-firewall.service <<'EOF'
[Unit]
Description=MASP ICAP port restriction
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
ExecStart=/usr/local/sbin/masp-firewall.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
EOF
        systemctl daemon-reload
        systemctl enable masp-firewall.service >/dev/null
        systemctl restart masp-firewall.service
    else
        /usr/local/sbin/masp-firewall.sh
    fi
    note "Port 1344 on $interface accepts only: ${ICAP_CLIENTS}"
fi

# ---------------------------------------------------------------------------
step "Acceptance checks"
./deploy/pilot/verify.sh --env-file "$ENV_FILE"

printf '\n===== MASP %s is installed =====\n' "$RELEASE_VERSION"
printf '  Console:      https://%s/console/  (user admin)\n' "$SERVER_NAME"
[[ ! -f "$CREDENTIALS_FILE" ]] || printf '  Password:     cat %s\n' "$CREDENTIALS_FILE"
[[ ${#ICAP_LIST[@]} -eq 0 ]] || printf '  ICAP:         icap://%s:1344/masp (REQMOD, preview off)\n' "$SERVER_IP"
[[ ! -f "$SSL_DIR/masp.csr" || -n "$CERT_FILE" ]] || printf '  Certificate:  temporary; send %s to the PKI team\n' "$SSL_DIR/masp.csr"
printf '  Log:          %s\n' "$LOG_FILE"
