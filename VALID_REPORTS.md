# Valid finding standard

A report is more likely to be valid when it includes:

- One clearly reproducible vulnerability or behavior
- Authorization-safe reproduction steps
- The exact affected URL, parameter, API method, or workflow
- Sanitized evidence with secrets and personal data removed
- A concrete security impact, not merely a scanner alert
- Affected account roles or object ownership relationships
- A clean control case where possible
- The expected versus actual behavior
- CWE and CVSS only when justified
- Duplicate and false-positive checks
- A second review before submission

BountyDeck must not convert a detection into a confirmed vulnerability automatically.
Automated findings should remain `Needs review` until a human verifies the impact and scope.
