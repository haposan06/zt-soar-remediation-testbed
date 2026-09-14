#!/usr/bin/env bash
# Copy Teleport-signed certs out of the read-only bind mount into a private
# directory owned by postgres with 0600 on the key, then hand off to the stock
# postgres entrypoint. Postgres refuses to start if ssl_key_file is group- or
# world-readable, which bind-mounted files on Docker Desktop for Mac always are.
set -euo pipefail

CERT_SRC=/certs-src
CERT_DST=/var/lib/postgresql/certs

if [ -f "$CERT_SRC/server.key" ]; then
  mkdir -p "$CERT_DST"
  cp "$CERT_SRC/server.crt" "$CERT_SRC/server.key" "$CERT_SRC/server.cas" "$CERT_DST/"
  chown -R postgres:postgres "$CERT_DST"
  chmod 0700 "$CERT_DST"
  chmod 0600 "$CERT_DST"/server.key
  chmod 0644 "$CERT_DST"/server.crt "$CERT_DST"/server.cas
  echo "pg-entrypoint: installed Teleport-signed certs into $CERT_DST"
else
  echo "pg-entrypoint: WARNING no $CERT_SRC/server.key found." >&2
  echo "pg-entrypoint: run scripts/setup.sh, which signs certs before starting postgres." >&2
  exit 1
fi

exec docker-entrypoint.sh "$@"
