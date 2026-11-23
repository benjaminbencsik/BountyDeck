# BountyDeck

BountyDeck is a self-hostable workspace for organizing authorized bug-bounty programs, manually recorded assets, and findings. It currently does **not** probe networks, run scans, or install third-party reconnaissance tools. Scope text is a human record, not a technical authorization check.

## Requirements

- Docker Engine and the Docker Compose plugin
- For VPS deployment: a Linux VPS, a DNS name pointing to it, and inbound TCP ports 80/443 available

No host-side Python, database, or scanner installation is needed; the application image installs only its Python web-app dependencies during the first build.

## Run locally

```sh
cp .env.example .env
# Replace both secrets; use a unique password and a random secret key.
# Example: openssl rand -hex 32
docker compose up --build -d
```

Open <http://localhost:8000>. To stop it, run `docker compose down`; your data remains in the `bountydeck-data` volume. To remove the data too, use `docker compose down -v` (destructive).

## Deploy on a VPS

1. Install Docker Engine and its Compose plugin using the official instructions for your Linux distribution.
2. Point a DNS A/AAAA record for your domain at the VPS. Allow inbound ports 80 and 443 in the host firewall and provider firewall.
3. Copy the repository to the VPS and create configuration:

   ```sh
   cp .env.example .env
   ```

4. Edit `.env`: set a unique long admin password, set `BOUNTYDECK_SECRET_KEY` to output from `openssl rand -hex 32`, set `BOUNTYDECK_HTTPS=1`, and set `BOUNTYDECK_DOMAIN` to the DNS name.
5. Start the app and Caddy reverse proxy:

   ```sh
   docker compose --profile vps up --build -d
   ```

Caddy obtains and renews HTTPS certificates automatically. Sign in at `https://your-domain`. Do not expose port 8000 publicly: Compose binds it to loopback only. Back up the Docker volume regularly and keep the `.env` file private (`chmod 600 .env`).

## Updating

Fetch the version you intend to deploy, then rebuild and restart:

```sh
git pull
docker compose --profile vps up --build -d
```

For local use, omit `--profile vps`. Database schema changes are applied on startup; back up the data volume before upgrades. Pin reviewed release tags or commit SHAs in production rather than deploying unreviewed changes from a moving branch.

## Current features

- Password-protected single-admin workspace
- Project/program records with policy URL, authorized scope text, and authorization notes
- Manual asset inventory and finding tracking
- Persistent SQLite storage, Docker-based local and VPS deployment, HTTPS reverse proxy option
- CSRF-protected forms, secure headers, non-root container user, and loopback-only app port

## Tooling status and safety

This starter does not provide the requested scanner suite or a tool installer/updater. Adding turnkey installers and automated execution for tools such as Nmap, ffuf, or Nuclei could enable scanning systems without authorization. The current app therefore stays a project and notes manager; it will not treat a user-entered scope list as proof of permission. Use security tools only under applicable written authorization and follow their official installation, update, and scope guidance.

## Data and security notes

The app has a single shared administrator account, not per-user accounts or team roles. Keep it behind HTTPS on a VPS, use strong unique secrets, restrict server access, and maintain encrypted backups. Do not store sensitive credentials or unredacted secrets as finding evidence. SQLite and the volume are intended for a small personal workspace; this is not yet a hardened multi-user production platform.
