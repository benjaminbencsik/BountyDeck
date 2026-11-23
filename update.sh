#!/usr/bin/env sh
# One-command install/update: pull the latest code, stamp the build with its commit, rebuild, restart.
# Your data lives in Docker volumes and is kept. Set COMPOSE_PROFILES in .env (e.g. vps,hunter)
# to choose which optional services are started.
set -eu
cd "$(dirname "$0")"
[ -f .env ] || { echo "Missing .env - copy .env.example to .env and fill it in first." >&2; exit 1; }
if [ -d .git ]; then
  git pull --ff-only
  GIT_SHA="$(git rev-parse HEAD)"
  export GIT_SHA
fi
docker compose up --build -d
docker compose ps
