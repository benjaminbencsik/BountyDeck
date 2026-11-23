# BountyDeck implementation status

## Available

- Local and VPS Docker deployment
- Tool image with pinned initial installs and explicit updates
- Scope parser for hosts, wildcard hosts, CIDR, and exclusions
- Public DNS resolution guardrails
- Team/auth primitives and role hierarchy
- Authorization, job lifecycle, audit, and normalized findings schemas
- Passive/light/intrusive profile planning
- Intrusive execution disabled by default
- Catalog of 15 manual bug-testing categories
- Test-plan and CSV reporting foundations
- PostgreSQL migration SQL under `migrations/`
- Redis/RQ production worker scaffold
- OpenAPI and Compose foundations

## Not yet enabled

- Live web-route integration for team accounts and scanner jobs
- PostgreSQL application runtime
- Live HTTP or DNS worker execution
- 2FA UI and API authentication middleware
- Scheduler and notifications
- PDF/HTML report rendering
- Screenshots and evidence object storage
- Metrics and OpenTelemetry
- Kubernetes manifests

## Execution gate

No command is executed by the web application or worker in this repository. Enable execution only after scope resolution, DNS validation, authorization approval, dry-run review, rate limits, and destination allowlists are integrated and tested.
