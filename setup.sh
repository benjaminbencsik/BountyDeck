#!/usr/bin/env sh
# First-run setup: checks prerequisites, creates .env with fresh random secrets, then builds and starts.
# Go, Python and the scanners are installed inside the Docker images, so Docker is the only host requirement.
# Usage: ./setup.sh [--no-start]
set -eu
cd "$(dirname "$0")"

command -v docker >/dev/null 2>&1 || { echo "Docker is required: https://docs.docker.com/engine/install/" >&2; exit 1; }
docker compose version >/dev/null 2>&1 || { echo "Docker Compose v2 is required (docker compose ...)." >&2; exit 1; }

rand_hex() { openssl rand -hex "$1" 2>/dev/null || python3 -c "import secrets,sys;print(secrets.token_hex(int(sys.argv[1])))" "$1"; }

if [ -f .env ]; then
  echo ".env already exists - leaving your settings untouched."
else
  PASSWORD="$(rand_hex 12)"
  SECRET="$(rand_hex 32)"
  cp .env.example .env
  sed -i.bak \
    -e "s|^BOUNTYDECK_ADMIN_PASSWORD=.*|BOUNTYDECK_ADMIN_PASSWORD=${PASSWORD}|" \
    -e "s|^BOUNTYDECK_SECRET_KEY=.*|BOUNTYDECK_SECRET_KEY=${SECRET}|" .env && rm -f .env.bak
  chmod 600 .env
  echo "Created .env. Admin password (also stored in .env): ${PASSWORD}"
fi

if [ "${1:-}" = "--no-start" ]; then
  echo "Skipping start (--no-start). Run ./update.sh to build and start."
  exit 0
fi

docker info >/dev/null 2>&1 || { echo "The Docker daemon is not reachable. Start Docker and re-run ./setup.sh." >&2; exit 1; }
./update.sh
echo
echo "Open http://localhost:8000 and sign in with the admin password above."
echo "Install the scanner toolset (first run only):  docker compose --profile tools run --rm tools"
echo "Scheduled hunting (optional):                  add hunter to COMPOSE_PROFILES in .env, then ./update.sh"
