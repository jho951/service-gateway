#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-dev}"

if [[ "$PROFILE" != "dev" && "$PROFILE" != "prod" ]]; then
  echo "usage: bash scripts/run.docker.sh [dev|prod] [docker compose options]" >&2
  exit 1
fi

if [[ $# -gt 0 ]]; then
  shift
fi

cd "$ROOT_DIR"
APP_ENV="$PROFILE" docker compose -f docker/docker-compose.yml up --build "$@"
