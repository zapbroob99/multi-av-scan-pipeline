#!/usr/bin/env bash
#
# Run the PostgreSQL-gated acceptance tests on the pilot host.
#
# These tests DROP AND RECREATE the target database's `public` schema, so they
# must never touch the pilot database. This script therefore always creates its
# own throwaway PostgreSQL container, runs the gated modules against it, and
# removes it again -- there is no option to point it at an existing database.
#
# The test suite is bind-mounted rather than baked into the application image:
# the deployed image handles untrusted samples, so its runtime surface is kept
# minimal. `tests/` ships in the release bundle for exactly this purpose.

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=common.sh
source "$SCRIPT_DIR/common.sh"

ENV_FILE=""
if [[ ${1:-} == "--env-file" ]]; then
    [[ $# -eq 2 ]] || pilot_die "usage: run_gated_tests.sh [--env-file PATH]"
    ENV_FILE="$2"
elif [[ $# -ne 0 ]]; then
    pilot_die "usage: run_gated_tests.sh [--env-file PATH]"
fi

pilot_init "$ENV_FILE"
pilot_require_command docker

TESTS_DIR="$PILOT_ROOT_DIR/tests"
[[ -d "$TESTS_DIR" ]] || pilot_die \
    "tests/ not found at $TESTS_DIR; use a release bundle that ships the test suite"

PG_CONTAINER="masp-pg-acceptance-$$"
PG_PASSWORD="acceptance-$(date +%s)"
NETWORK="$(pilot_compose ps --format '{{.Name}}' app 2>/dev/null | head -1)"
if [[ -n "$NETWORK" ]]; then
    NETWORK="$(docker inspect -f '{{range $k,$v := .NetworkSettings.Networks}}{{$k}}{{end}}' \
        "$NETWORK" 2>/dev/null | head -1)"
fi
[[ -n "$NETWORK" ]] || pilot_die "could not determine the pilot compose network; is the stack up?"

cleanup() {
    docker rm -f "$PG_CONTAINER" >/dev/null 2>&1 || true
}
trap cleanup EXIT

printf '== starting throwaway PostgreSQL (%s) ==\n' "$PG_CONTAINER"
docker run -d --name "$PG_CONTAINER" --network "$NETWORK" \
    -e POSTGRES_DB=masp -e POSTGRES_USER=masp -e POSTGRES_PASSWORD="$PG_PASSWORD" \
    "${MASP_POSTGRES_IMAGE:-postgres:16-alpine}" >/dev/null

printf 'waiting for it to accept connections'
for _ in $(seq 1 60); do
    if docker exec "$PG_CONTAINER" pg_isready -U masp -d masp >/dev/null 2>&1; then
        printf ' ready\n'
        break
    fi
    printf '.'
    sleep 2
done
docker exec "$PG_CONTAINER" pg_isready -U masp -d masp >/dev/null 2>&1 \
    || pilot_die "throwaway PostgreSQL did not become ready"

printf '\n== PostgreSQL-gated acceptance ==\n'
# `run --rm` starts a one-off container from the app image with the test suite
# mounted read-only. Every gated case must RUN; a skip means the URL never
# reached the tests and the gate did not actually execute.
set +e
pilot_compose run --rm \
    -v "$TESTS_DIR:/app/tests:ro" \
    -e MASP_TEST_POSTGRES_URL="postgresql://masp:$PG_PASSWORD@$PG_CONTAINER:5432/masp" \
    app python -m unittest \
    tests.test_db_concurrent_init \
    tests.test_reliability_postgres \
    tests.test_worker_heartbeat_concurrency \
    tests.test_worker_fencing_concurrency \
    tests.test_archive_finalization_integration -v
status=$?
set -e

if [[ $status -ne 0 ]]; then
    pilot_die "PostgreSQL-gated acceptance FAILED; do not proceed to user traffic"
fi

printf '\nPostgreSQL-gated acceptance PASSED.\n'
printf 'Confirm the output above reports 0 skipped, then retain it in the acceptance record.\n'
