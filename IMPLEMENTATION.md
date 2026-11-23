# BountyDeck roadmap status

## Added foundations

- Team and API credential primitives
- Role hierarchy for viewer, operator, approver, and admin
- Password hashing with PBKDF2-SHA256
- API token digest storage
- Project membership schema
- Authorization, scan-job, raw-result, and normalized-finding schemas
- Scope-validated dry-run planning
- Passive/light/intrusive profile separation
- Intrusive execution block
- Queue worker that refuses network execution until a future approval implementation enables it
- Unit tests for passive planning and out-of-scope rejection

## Before public execution

1. Replace SQLite with PostgreSQL migrations.
2. Integrate team accounts into every web route.
3. Store and approve immutable authorization records.
4. Validate DNS resolution and redirects before workers receive targets.
5. Add a second approver for intrusive jobs.
6. Implement isolated network worker containers and command allowlists.
7. Store raw output and normalized evidence.
8. Add scheduling and notification services.

## Test

```sh
python -m venv .venv
. .venv/bin/activate
pip install -r requirements.txt -r requirements-dev.txt
pytest -q
```
