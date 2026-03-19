#!/usr/bin/env bash

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT_DIR="$(cd "$SCRIPT_DIR/.." && pwd)"
PROFILE="${1:-dev}"

if [[ "$PROFILE" != "dev" && "$PROFILE" != "prod" ]]; then
  echo "usage: bash scripts/run.local.sh [dev|prod]" >&2
  exit 1
fi

cd "$ROOT_DIR"
APP_ENV="$PROFILE" ./gradlew run --args="--profile=$PROFILE"
