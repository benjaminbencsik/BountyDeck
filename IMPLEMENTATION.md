# BountyDeck implementation status

## Implemented

- Docker deployment for local hosts and VPS reverse-proxy deployment
- Persistent SQLite workspace, password login, CSRF protection, security headers
- Project, asset, finding, and tool registry records
- Pinned initial tool installation and explicit update mode
- Strict domain/wildcard/CIDR scope parser and exclusion rules
- Unit tests for scope matching
- Redis/RQ production worker and PostgreSQL infrastructure templates
- OpenAPI starter specification
- Read-only tool volume mount in the web container

## Deliberately not yet enabled

- Automated network execution from the web UI
- Intrusive or active scanners
- Team users and roles
- 2FA and API-key authentication
- PostgreSQL-backed application storage
- Browser screenshot storage
- Scheduling UI
- Result normalization pipelines
- PDF/JSON/CSV reporting

## Required before scanner execution

1. Import or create scope and get sign-off approval.
2. Convert scope into immutable rules.
3. Validate every target against exact, wildcard, CIDR, and exclusion rules.
4. Require a scan profile and confirmation of written authorization.
5. Preview commands and targets in a dry-run view.
6. Send approved jobs through Redis to isolated workers.
7. Record raw output and immutable audit events.
8. Enforce timeouts, rate limits, destination allowlists, and cancellation.

## Run scope tests

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```
