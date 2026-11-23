# Evidence handling

Evidence must be minimized and redacted before sharing or storage:

- Remove live session cookies and bearer tokens
- Redact personal or customer data
- Replace private infrastructure addresses when not necessary
- Keep the smallest reproducible sample
- Preserve the request/response context needed to evaluate impact
- Record test accounts and timestamps
- Never attach production secrets or unrelated data

The evidence redaction helper is conservative and must not be treated as a complete data-loss-prevention system.
