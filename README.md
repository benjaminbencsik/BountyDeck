# BountyDeck

BountyDeck is a self-hostable workspace for authorized bug-bounty program, asset, and finding management. It runs locally or behind HTTPS on a VPS.

## Features

- Programs, scope rules, assets and findings in one place, with Markdown/JSON export per project.
- **Scope matching in code.** Rules like `example.com`, `*.example.com`, CIDR ranges and `!excluded.example.com` (exclusions always win). Recorded assets show an in-scope / out-of-scope badge.
- **Scheduled hunting** (opt-in per project): while you are away, a separate `hunter` service discovers subdomains for your wildcard rules (subfinder), probes live hosts (httpx) and runs low-impact nuclei templates, then drops the results into your workspace as **Unverified** findings. New in-scope assets and findings can ping a Discord/Slack webhook.
- Finding workflow statuses including *Unverified*, *Verified* and *False positive*. Marking a finding Verified or False positive requires a note on how you confirmed it, and a **verified-only report** export leaves everything else out.
- Login lockout after repeated failures, strict CSP, CSRF protection.
- In-app **Updates** page that checks GitHub for a newer commit; `./update.sh` applies it in one command.

## Safety model

BountyDeck distinguishes between a scope record and authorization to test. The scope rules you write are enforced by the hunter in code, but they are only as good as the policy you copied them from.

- Automation is **off by default**. Enabling it for a project requires ticking that the program's policy permits automated scanning. Disabling it stops a run in progress at its next stage.
- Every host is matched against the project's scope before it is passed to any tool, including hosts a tool discovered itself. Out-of-scope results are dropped and logged.
- Only subfinder, httpx and nuclei run, with fixed arguments (no shell), a request-rate cap (`BOUNTYDECK_HUNT_RATE`, default 10/s), and intrusive/DoS/fuzzing/brute-force nuclei templates excluded. Nuclei out-of-band (interactsh) callbacks are disabled.
- Scanner output is frequently a false positive. Hunter results are stored as *Unverified*; reproduce each one by hand before reporting.
- Heavier tools (ffuf, naabu, nmap, dirsearch) are in the tools image for manual use but are never run automatically.

## Requirements

- Docker Engine and Docker Compose
- Linux, macOS, or Windows host with Docker
- A VPS with inbound ports 80/443 and DNS for HTTPS deployment

## First-time setup

The quick way: `./setup.sh` checks for Docker, creates `.env` with fresh random secrets (it prints the admin password once), then builds and starts everything. Go, Python and the scanners are installed inside the Docker images, so Docker is the only host requirement. The manual steps are below.

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
- TLSx, Hakrawler, GoSpider, wafw00f (manual use; the hunter service never runs these)

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

## Scheduled hunting

```sh
# 1. Start the hunter service (add `hunter` to COMPOSE_PROFILES in .env to keep it on across updates).
docker compose --profile hunter up --build -d
# 2. In the web UI, open a project and use "Enable scheduled hunting".
# 3. Optional: set BOUNTYDECK_WEBHOOK_URL (https://) in .env for run summaries.
```

Use **Run now** on a project to queue an immediate run. Run history and logs are shown on the project card. The service needs outbound internet access for subfinder/nuclei, and nuclei downloads its templates on first use.

## Application updates

The **Updates** page in the app checks GitHub for a newer commit. To apply an update, run one command on the host:

```sh
./update.sh   # git pull, rebuild, restart; data volumes are kept
```

Set `COMPOSE_PROFILES=vps,hunter` (whichever you use) in `.env` so `update.sh` restarts the right services. Back up `bountydeck-data` before major upgrades.

## Development

```sh
pip install -r requirements.txt -r requirements-dev.txt
python -m pytest -q
```

## Security and operations

- The app is protected with a single strong administrator password.
- SQLite data persists in `bountydeck-data`.
- Port 8000 is bound to `127.0.0.1`; the VPS path uses Caddy.
- Back up the volumes and `.env` securely.
- Restrict Docker host access, because Docker socket or container privileges can bypass ordinary user permissions.
- The tools container is not exposed to the internet or the web UI.
- Review third-party licenses and source integrity before production use.
