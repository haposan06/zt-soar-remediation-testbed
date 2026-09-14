#!/usr/bin/env bash
# Tear the lab down. Default stops containers; --purge also deletes volumes,
# certs, identity files and every generated artefact (including the audit log).
set -euo pipefail
LAB_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COMPOSE="docker compose -f $LAB_DIR/docker-compose.yml"

if [ "${1:-}" = "--purge" ]; then
  echo "==> Removing containers, volumes and all generated artefacts"
  $COMPOSE down -v --remove-orphans || true
  rm -f  "$LAB_DIR"/certs/server.* "$LAB_DIR"/identities/*.pem
  rm -rf "$LAB_DIR"/audit/* "$LAB_DIR"/out/* "$LAB_DIR"/tsh-home/*
  echo "==> Purged. NOTE: the audit log has been deleted."
else
  echo "==> Stopping containers (volumes, audit log and identities kept)"
  $COMPOSE down --remove-orphans || true
  echo "==> Stopped. Use --purge to also delete volumes and generated data."
fi
