# BountyDeck implementation status

## Implemented foundations

- Docker deployment for local hosts and VPS reverse-proxy deployment
- Persistent SQLite workspace and password authentication
- Project, asset, finding, tool registry, and audit foundations
- Pinned tool installation and explicit update mode
- Strict domain, wildcard-domain, CIDR, and exclusion parsing
- Unit tests for scope matching
- Redis/RQ worker and PostgreSQL infrastructure templates
- OpenAPI starter specification
- Read-only tool volume in the web container

## Safety gates before execution

No endpoint in this repository automatically executes a scanner. Before enabling execution:

1. Create an immutable project authorization record.
2. Parse scope into exact, wildcard, CIDR, and exclusion rules.
3. Validate every resolved address and redirect destination.
4. Require the operator to acknowledge authorization and select a documented profile.
5. Preview the exact command and target list as a dry run.
6. Send only approved jobs to isolated workers.
7. Record tool version, command, raw output, and audit event.
8. Enforce timeouts, rate limits, cancellation, and destination allowlists.

## Test locally

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```
