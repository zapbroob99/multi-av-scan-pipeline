#!/usr/bin/env bash
# TLS reverse proxy rehearsal on an isolated, disposable project.
#
# Starts PostgreSQL and the app from docker-compose.pilot.yml under the project
# name "masp-tls" (never the real pilot), puts nginx with a self-signed
# certificate in front, and checks what the runbook's TLS section promises:
#
#   untrusted proxy (FORWARDED_ALLOW_IPS=127.0.0.1): console login is refused by
#     the same-origin check and worker control is refused as non-HTTPS;
#   trusted proxy (MASP_FORWARDED_ALLOW_IPS=<proxy address>): login succeeds with
#     a Secure cookie, a CSRF-protected console write succeeds, and a remote
#     worker enrolls and heartbeats through HTTPS.
#
# Everything it creates is removed on exit. Uses local ports 18443 (proxy),
# 18097 (app) and 18344 (ICAP, unused). Usage: deploy/pilot/rehearse_tls.sh
set -uo pipefail

REPO="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
WORK="$(mktemp -d)"
PROJECT=masp-tls
PORT=18443
FAILURES=0
cd "$REPO"
mkdir -p "$WORK/storage" "$WORK/rules" "$WORK/tls"

# The first interpreter that actually runs (on Windows, python3 can be a Store stub).
PY=""
for candidate in python3 python; do
    if "$candidate" -c 'pass' >/dev/null 2>&1; then PY="$candidate"; break; fi
done
[[ -n "$PY" ]] || { echo "python3 is required"; exit 1; }
rand() { "$PY" -c 'import secrets; print(secrets.token_urlsafe(24))'; }
# Native Windows tools (Git Bash) need Windows paths; elsewhere this is a no-op.
winpath() { cygpath -m "$1" 2>/dev/null || printf '%s' "$1"; }
ADMIN_PASSWORD="$(rand)"; ENROLL="$(rand)"; PG_PASSWORD="$(rand)"; API_TOKEN="$(rand)"

compose() { docker compose -p "$PROJECT" -f docker-compose.pilot.yml --env-file "$(winpath "$WORK/env")" "$@"; }
cleanup() {
    docker rm -f masp-tls-proxy >/dev/null 2>&1
    compose down -v >/dev/null 2>&1
    docker rmi masp-tls:local >/dev/null 2>&1
    rm -rf "$WORK"
}
trap cleanup EXIT

write_env() {  # $1 = FORWARDED_ALLOW_IPS for the app. Secrets stay fixed for the run.
    "$PY" - "$(winpath "$REPO/.env.pilot.example")" "$(winpath "$WORK/env")" "$1" \
        "$(winpath "$WORK/storage")" "$(winpath "$WORK/rules")" \
        "$ADMIN_PASSWORD" "$ENROLL" "$PG_PASSWORD" "$API_TOKEN" <<'PYSRC'
import sys
src, dst, allow, storage, rules, admin, enroll, pg_password, api_token = sys.argv[1:]
override = {
    "MASP_IMAGE": "masp-tls:local", "MASP_POSTGRES_PASSWORD": pg_password,
    "MASP_API_TOKEN": api_token, "MASP_ADMIN_PASSWORD": admin,
    "MASP_APP_BIND": "127.0.0.1:18097", "MASP_STORAGE_DIR": storage, "MASP_RULES_DIR": rules,
    "MASP_UPLOAD_MAX_BYTES": "52428800", "MASP_ICAP_MAX_BYTES": "52428800",
    "MASP_ICAP_BIND": "127.0.0.1:18344", "MASP_ICAP_ALLOWED_IPS": "127.0.0.1",
    "MASP_WORKER_ENROLLMENT_TOKEN": enroll, "MASP_FORWARDED_ALLOW_IPS": allow,
    "MASP_SESSION_SECURE": "", "MASP_WORKER_CONTROL_REQUIRE_HTTPS": "1",
}
out, seen = [], set()
for line in open(src, encoding="utf-8"):
    key = line.split("=", 1)[0].strip()
    if "=" in line and not line.lstrip().startswith("#") and key in override:
        out.append(f"{key}={override[key]}\n"); seen.add(key)
    else:
        out.append(line)
out += [f"{k}={v}\n" for k, v in override.items() if k not in seen]
open(dst, "w", encoding="utf-8").writelines(out)
PYSRC
}

expect() {  # label, actual, expected
    if [[ "$2" == "$3" ]]; then printf '  PASS %s (%s)\n' "$1" "$2"
    else printf '  FAIL %s: got %s, expected %s\n' "$1" "$2" "$3"; FAILURES=$((FAILURES + 1)); fi
}

json_field() { "$PY" -c 'import json,sys; print(json.load(open(sys.argv[1])).get(sys.argv[2], ""))' "$(winpath "$1")" "$2" 2>/dev/null; }

probe() {  # $1 = trusted|untrusted
    local base="https://localhost:$PORT" jar="$WORK/jar" node
    rm -f "$jar"
    node='{"node_id":"tls-node","display_name":"TLS node","hostname":"tls-host","platform":"linux","agent_version":"rehearsal","labels":{},"capacity":1,"engine_keys":[],"process_id":1}'
    expect "console page" "$(curl -sk -o /dev/null -w '%{http_code}' "$base/console/")" 200
    local login secure=no csrf write enroll agent beat
    login=$(curl -sk -D "$WORK/login.h" -c "$(winpath "$jar")" -o "$(winpath "$WORK/login.json")" -w '%{http_code}' \
        -H "Origin: $base" -H 'X-MASP-UI: 1' -H 'Content-Type: application/json' \
        -d "{\"username\":\"admin\",\"password\":\"$ADMIN_PASSWORD\"}" "$base/api/ui/v1/session/login")
    grep -qi '^set-cookie:.*; *secure' "$WORK/login.h" && secure=yes
    enroll=$(curl -sk -o "$(winpath "$WORK/enroll.json")" -w '%{http_code}' -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $ENROLL" -d "$node" "$base/api/v1/worker-control/enroll")
    if [[ "$1" == untrusted ]]; then
        expect "login refused by the same-origin check" "$login" 403
        expect "worker control refused as non-HTTPS" "$enroll" 400
        return
    fi
    expect "login" "$login" 200
    expect "session cookie Secure" "$secure" yes
    csrf=$(json_field "$WORK/login.json" csrf_token)
    write=$(curl -sk -b "$(winpath "$jar")" -o /dev/null -w '%{http_code}' \
        -H "Origin: $base" -H 'X-MASP-UI: 1' -H "X-CSRF-Token: $csrf" -H 'Content-Type: application/json' \
        -d "{\"list_kind\":\"block\",\"hashes\":[\"$(printf '%064d' 0)\"],\"note\":\"tls rehearsal\"}" \
        "$base/api/ui/v1/hash-list")
    expect "CSRF-protected console write" "$write" 201
    expect "worker enrollment" "$enroll" 201
    agent=$(json_field "$WORK/enroll.json" agent_token)
    beat=$(curl -sk -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' \
        -H "Authorization: Bearer $agent" -d "$node" "$base/api/v1/worker-control/heartbeat")
    expect "worker heartbeat" "$beat" 200
}

wait_healthy() { for _ in $(seq 1 90); do curl -skf "https://localhost:$PORT/health" >/dev/null && return 0; sleep 2; done; return 1; }

echo "== building and starting PostgreSQL and the app (project $PROJECT)"
MSYS_NO_PATHCONV=1 openssl req -x509 -newkey rsa:2048 -nodes -days 2 -subj "/CN=localhost" \
    -keyout "$(winpath "$WORK/tls/key.pem")" -out "$(winpath "$WORK/tls/cert.pem")" >/dev/null 2>&1 \
    || { echo "openssl failed"; exit 1; }
cat > "$WORK/tls/nginx.conf" <<'NGINX'
server {
    listen 8443 ssl;
    ssl_certificate /etc/nginx/tls/cert.pem;
    ssl_certificate_key /etc/nginx/tls/key.pem;
    client_max_body_size 64m;
    resolver 127.0.0.11 valid=5s;
    set $upstream http://app:8000;
    location / {
        proxy_pass $upstream;
        proxy_set_header Host $http_host;
        proxy_set_header X-Forwarded-Proto https;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
    }
}
NGINX
write_env 127.0.0.1
compose up -d --build postgres >/dev/null 2>&1 || { echo "PostgreSQL did not start"; exit 1; }
# The app normally waits for ClamAV; this check does not need it.
compose up -d --no-deps --build app >/dev/null 2>&1 || { echo "app did not start"; compose logs --tail 20 app; exit 1; }
MSYS_NO_PATHCONV=1 docker run -d --name masp-tls-proxy --network "${PROJECT}_default" -p "127.0.0.1:$PORT:8443" \
    -v "$(winpath "$WORK/tls/nginx.conf"):/etc/nginx/conf.d/default.conf:ro" \
    -v "$(winpath "$WORK/tls"):/etc/nginx/tls:ro" nginx:stable-alpine >/dev/null || { echo "proxy did not start"; exit 1; }
PROXY_IP=$(docker inspect -f '{{range .NetworkSettings.Networks}}{{.IPAddress}}{{end}}' masp-tls-proxy)
wait_healthy || { echo "app not reachable through the proxy"; docker logs --tail 10 masp-tls-proxy; exit 1; }

echo "== untrusted proxy (FORWARDED_ALLOW_IPS=127.0.0.1): these must fail"
probe untrusted

echo "== trusted proxy (MASP_FORWARDED_ALLOW_IPS=$PROXY_IP): these must pass"
write_env "$PROXY_IP"
compose up -d --no-deps --force-recreate app >/dev/null 2>&1
sleep 3
wait_healthy || { echo "app not reachable after recreate"; compose logs --tail 20 app; exit 1; }
probe trusted

if [[ $FAILURES -eq 0 ]]; then echo "RESULT: PASS"; else echo "RESULT: FAIL ($FAILURES check(s))"; exit 1; fi
