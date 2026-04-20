#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-local}"
ENV_FILE="${APP_ENV_FILE:-.env.local}"

if [[ "$PROFILE" != "local" ]]; then
  echo "usage: bash scripts/run.local.sh [local]" >&2
  exit 1
fi

cd "$ROOT_DIR"
if [[ ! -f "$ENV_FILE" ]]; then
  echo "local env file not found: $ENV_FILE" >&2
  echo "copy .env.example to .env.local and set GATEWAY_INTERNAL_REQUEST_SECRET" >&2
  exit 1
fi

export GATEWAY_INTERNAL_REQUEST_SECRET="${GATEWAY_INTERNAL_REQUEST_SECRET:-local-authz-internal-secret}"

APP_ENV="$PROFILE" APP_ENV_FILE="$ENV_FILE" ./gradlew run --args="--profile=$PROFILE --env-file=$ENV_FILE"
