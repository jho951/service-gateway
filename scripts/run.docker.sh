#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-local}"

if [[ "$PROFILE" != "local" && "$PROFILE" != "prod" ]]; then
  echo "usage: bash scripts/run.docker.sh [local|prod] [docker compose options]" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  shift
fi

cd "$ROOT_DIR"
SHARED_NETWORK="${SHARED_SERVICE_NETWORK:-${BACKEND_SHARED_NETWORK:-${MSA_SHARED_NETWORK:-service-backbone-shared}}}"
docker network inspect "$SHARED_NETWORK" >/dev/null 2>&1 || docker network create "$SHARED_NETWORK" >/dev/null
if [[ "$PROFILE" == "local" ]]; then
  COMPOSE_FILE="docker/docker-compose.dev.yml"
else
  COMPOSE_FILE="docker/docker-compose.prod.yml"
fi

APP_ENV="$PROFILE" SHARED_SERVICE_NETWORK="$SHARED_NETWORK" BACKEND_SHARED_NETWORK="$SHARED_NETWORK" MSA_SHARED_NETWORK="$SHARED_NETWORK" docker compose -f "$COMPOSE_FILE" up --build "$@"
