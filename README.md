# BountyDeck

BountyDeck is a self-hostable workspace for authorized bug-bounty program, asset, and finding management. It runs locally or behind HTTPS on a VPS.

## Safety model

BountyDeck distinguishes between a scope record and authorization to scan. It does not convert a domain string or a checkbox into permission. Before running an intrusive tool, retain written authorization and follow the target owner's rules. Keep tools disabled until a project-specific review is complete. This repository provides installation/update tooling, not unrestricted one-click target scanning.

## Requirements

- Docker Engine and Docker Compose
- Linux, macOS, or Windows host with Docker
- A VPS with inbound ports 80/443 and DNS for HTTPS deployment

## First-time setup

```sh
cp .env.example .env
openssl rand -hex 32  # use one value for BOUNTYDECK_SECRET_KEY
# Set a strong BOUNTYDECK_ADMIN_PASSWORD in .env

# Build and install the web application.
docker compose up --build -d

# Initial tool installation and Nuclei template download.
docker compose --profile tools run --rm tools
```

Open `http://localhost:8000` locally. The tools volume persists under `bountydeck-tools` and is mounted read-only in the web app. Stop with `docker compose down`.

## VPS deployment

Point DNS at the server, open 80/443, copy this repository, and configure `.env`:

```dotenv
BOUNTYDECK_ADMIN_PASSWORD=<strong unique password>
BOUNTYDECK_SECRET_KEY=<openssl rand -hex 32>
BOUNTYDECK_HTTPS=1
BOUNTYDECK_DOMAIN=bounty.example.com
```

Start application and HTTPS proxy:

```sh
docker compose --profile vps up --build -d
docker compose --profile tools run --rm tools
```

Caddy requests and renews TLS certificates automatically.

## Tool suite

The initial Docker tool image includes these scanners and helpers:

- Subfinder, Amass, Assetfinder, DNSx, dig, and Whois
- HTTPx and Katana
- Naabu and Nmap
- Gau and Waybackurls
- FFUF and Dirsearch
- Nuclei plus downloaded templates
- Gowitness

See `tools/tool-registry.json` for categories and risk labels. The image pins reviewed tool versions for reproducible first installs. Tool binaries and templates are kept in the persistent Docker volume `bountydeck-tools`; the web container cannot alter or execute them because the mount is read-only.

## Download or update tools later

```sh
# Reinstall or initialize tools after a fresh Docker volume.
docker compose --profile tools run --rm tools

# Update Go tools to latest, upgrade Dirsearch, and refresh Nuclei templates.
docker compose --profile tools run --rm tools-update update

# Display a status shell or registry.
docker compose --profile tools run --rm tools shell
docker compose --profile tools run --rm tools status
```

Updates are intentionally run explicitly. Production deployments should test updated binaries and templates before use. Rebuilding `Dockerfile.tools` also changes its pinned tool versions on the next initial-install run.

## Application updates

```sh
git pull
docker compose --profile vps up --build -d
# Back up bountydeck-data before a major upgrade.
docker compose ps
```

## Security and operations

- The app is protected with a single strong administrator password.
- SQLite data persists in `bountydeck-data`.
- Port 8000 is bound to `127.0.0.1`; the VPS path uses Caddy.
- Back up the volumes and `.env` securely.
- Restrict Docker host access, because Docker socket or container privileges can bypass ordinary user permissions.
- The tools container is not exposed to the internet or the web UI.
- Review third-party licenses and source integrity before production use.
