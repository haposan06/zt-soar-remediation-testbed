#!/usr/bin/env bash
# =====================================================================
# Monash thesis lab - bring up Teleport + PostgreSQL and provision users.
#
# SAFETY: every tsh/tctl invocation is pinned to the lab.
#   * tctl runs INSIDE the teleport container (never against a real cluster).
#   * tsh always runs with TELEPORT_HOME=<lab>/tsh-home and
#     --proxy=localhost:3080 --insecure, so the operator's own
#     ~/.tsh profile (which may be logged into an unrelated cluster) is never read or written.
#
# Usage:
#   ./scripts/setup.sh            # idempotent bring-up
#   ./scripts/setup.sh --resign   # also re-sign the Postgres server certs
#   ./scripts/setup.sh --reset    # destroy volumes and rebuild from scratch
# =====================================================================
set -euo pipefail

LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$LAB_DIR"

COMPOSE="docker compose -f $LAB_DIR/docker-compose.yml"
TP_CONTAINER=thesis-teleport
PG_CONTAINER=thesis-postgres
PROXY=localhost:3080
CERT_TTL=2190h          # ~91 days, per the Teleport self-hosted Postgres guide
IDENTITY_TTL=24h

# Hard isolation from any other cluster the operator may be logged into.
export TELEPORT_HOME="$LAB_DIR/tsh-home"
mkdir -p "$TELEPORT_HOME" "$LAB_DIR/certs" "$LAB_DIR/audit" "$LAB_DIR/identities" "$LAB_DIR/out"
chmod 700 "$TELEPORT_HOME"

TSH=/usr/local/bin/tsh
tctl() { docker exec "$TP_CONTAINER" /usr/local/bin/tctl "$@"; }
log()  { printf '\033[1;34m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[1;33m[warn]\033[0m %s\n' "$*" >&2; }
die()  { printf '\033[1;31m[fail]\033[0m %s\n' "$*" >&2; exit 1; }

RESIGN=0; RESET=0
for a in "$@"; do
  case "$a" in
    --resign) RESIGN=1 ;;
    --reset)  RESET=1; RESIGN=1 ;;
    *) die "unknown flag: $a" ;;
  esac
done

# --- 0. preflight ----------------------------------------------------
docker info >/dev/null 2>&1 || die "Docker daemon is not running. Start Docker Desktop and retry."
[ -x "$TSH" ] || die "tsh not found at $TSH"

if [ "$RESET" = 1 ]; then
  log "Reset: tearing down containers and volumes"
  $COMPOSE down -v --remove-orphans || true
  rm -f "$LAB_DIR"/certs/server.* "$LAB_DIR"/identities/*.pem
  rm -rf "$LAB_DIR"/audit/* "$LAB_DIR"/tsh-home/*
fi

wait_healthy() {          # wait_healthy <container> <seconds>
  local c="$1" limit="${2:-120}" i=0 st
  while [ "$i" -lt "$limit" ]; do
    st="$(docker inspect --format '{{if .State.Health}}{{.State.Health.Status}}{{else}}none{{end}}' "$c" 2>/dev/null || echo missing)"
    [ "$st" = healthy ] && { log "$c is healthy"; return 0; }
    sleep 2; i=$((i+2))
  done
  docker logs --tail 40 "$c" || true
  die "$c did not become healthy within ${limit}s"
}

# --- 1. Teleport first (it owns the CA that signs the Postgres certs) -
log "Starting Teleport"
$COMPOSE up -d teleport
wait_healthy "$TP_CONTAINER" 150

# --- 2. Sign the PostgreSQL server certificate ------------------------
# Docs: enroll-self-hosted-databases/postgres-self-hosted (Step 2/5).
# --format=db writes server.cas, server.crt and server.key. --host must match
# the hostname the Database Service dials, i.e. the compose service `postgres`.
if [ "$RESIGN" = 1 ] || [ ! -f "$LAB_DIR/certs/server.key" ]; then
  log "Signing PostgreSQL server certs (tctl auth sign --format=db --host=postgres)"
  tctl auth sign --format=db --host=postgres --out=/certs/server --ttl="$CERT_TTL" --overwrite >/dev/null
  for f in server.cas server.crt server.key; do
    [ -s "$LAB_DIR/certs/$f" ] || die "expected certs/$f was not produced"
  done
  log "Wrote certs/server.{cas,crt,key}"
  # Certs changed -> Postgres must be restarted to pick them up.
  docker ps -q -f name="$PG_CONTAINER" | grep -q . && $COMPOSE restart postgres || true
else
  log "Reusing existing certs/server.* (pass --resign to regenerate)"
fi

# --- 3. PostgreSQL ----------------------------------------------------
log "Starting PostgreSQL"
$COMPOSE up -d postgres
wait_healthy "$PG_CONTAINER" 150

log "Verifying TLS + cert auth are actually on"
ssl_on="$(docker exec "$PG_CONTAINER" psql -U postgres -d procurement -tAc 'SHOW ssl;' | tr -d '[:space:]')"
[ "$ssl_on" = "on" ] || die "PostgreSQL did not start with ssl=on"
docker exec "$PG_CONTAINER" psql -U postgres -d procurement -tAc \
  "SELECT count(*) FROM public.payments" >/dev/null || die "procurement schema missing"

# --- 4. Teleport users ------------------------------------------------
# `tctl users add --db-users --db-names --roles=access` per the Teleport
# self-hosted Postgres guide. Recreated each run so the traits stay in sync.
#   name|db_users|db_names
# Identity naming and the db_role catalogue are mandated by
# ../../lab/harness/alerts_schema.md (roles: app_service, analyst_ro,
# proc_officer, dba; teleport_user is an email address).
#   name|db_users|db_names
USERS=(
  "svc.app@eproc.test|app_service|procurement"
  "rina.hartono@eproc.test|analyst_ro|procurement"
  "priya.suryani@eproc.test|analyst_ro|procurement"
  "dave.wijaya@eproc.test|proc_officer|procurement"
  "nina.lestari@eproc.test|proc_officer|procurement"
  "carol.tan@eproc.test|dba|procurement,postgres"
  "eve.contractor@eproc.test|analyst_ro|procurement"
)

log "Creating Teleport users"
for row in "${USERS[@]}"; do
  IFS='|' read -r name dbusers dbnames <<<"$row"
  tctl users rm "$name" >/dev/null 2>&1 || true
  tctl users add "$name" --roles=access --db-users="$dbusers" --db-names="$dbnames" >/dev/null
  printf '    %-16s db_users=%-12s db_names=%s\n' "$name" "$dbusers" "$dbnames"
done

# --- 5. Non-interactive credentials ----------------------------------
# NOTE ON MFA: Teleport 17.7.x refuses to boot with `second_factor: "off"`
# ("cannot disable multi-factor authentication"), so an interactive
# `tsh login --user=... ` would demand an OTP enrolled through the browser.
# We therefore never log in interactively. `tctl auth sign --user=<u>` mints a
# complete identity file straight from the Auth Service, which bypasses the
# second-factor prompt. Every tsh call then uses `tsh -i <identity>`.
# => THERE IS NO MANUAL BROWSER STEP. The whole lab is scripted.
log "Signing identity files (non-interactive; no browser step required)"
for row in "${USERS[@]}"; do
  IFS='|' read -r name _ _ <<<"$row"
  tctl auth sign --user="$name" --format=file --ttl="$IDENTITY_TTL" \
       --out="/identities/${name}.pem" --overwrite >/dev/null 2>&1
  [ -s "$LAB_DIR/identities/${name}.pem" ] || die "identity for $name was not created"
  chmod 600 "$LAB_DIR/identities/${name}.pem"
  printf '    identities/%s.pem\n' "$name"
done

# --- 6. Verify the whole path ----------------------------------------
log "Verifying database is reachable through Teleport as svc.app@eproc.test"
"$TSH" -i "$LAB_DIR/identities/svc.app@eproc.test.pem" --proxy="$PROXY" --insecure db ls 2>/dev/null \
  | sed 's/^/    /'

cat <<EOF

$(log "Lab is up.")
  Teleport web UI : https://localhost:3080  (self-signed cert -> accept the warning)
  Audit log (JSON): $LAB_DIR/audit/<YYYY-MM-DD>.00:00:00.log
  Identity files  : $LAB_DIR/identities/*.pem   (TTL $IDENTITY_TTL - re-run this script to refresh)

Next:
  python3 scripts/corpus.py --days 14 --benign-target 48000 --seed 42
  python3 scripts/collect_audit.py
  python3 scripts/detect.py
EOF
