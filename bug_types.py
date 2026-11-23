BUG_TEST_TYPES = {
    "broken-access-control": {
        "name": "Broken access control / IDOR",
        "risk": "high",
        "checks": ["object ownership", "role boundaries", "horizontal authorization", "vertical authorization", "direct object references"],
    },
    "authentication": {
        "name": "Authentication and session security",
        "risk": "high",
        "checks": ["password policy", "session lifecycle", "logout", "MFA", "credential recovery", "account lockout"],
    },
    "injection": {
        "name": "Injection",
        "risk": "critical",
        "checks": ["SQL", "NoSQL", "command", "LDAP", "template", "header", "log injection"],
    },
    "xss": {
        "name": "Cross-site scripting",
        "risk": "high",
        "checks": ["stored context", "reflected context", "DOM context", "sanitization", "CSP"],
    },
    "ssrf": {
        "name": "Server-side request forgery",
        "risk": "critical",
        "checks": ["URL import", "webhook", "metadata destinations", "redirects", "internal network reachability"],
    },
    "csrf": {
        "name": "Cross-site request forgery",
        "risk": "medium",
        "checks": ["state-changing forms", "origin", "token binding", "cookie settings", "same-site policy"],
    },
    "open-redirect": {
        "name": "Open redirect",
        "risk": "medium",
        "checks": ["redirect parameters", "allowlisted destinations", "protocol confusion", "authentication flows"],
    },
    "cors": {
        "name": "CORS and cross-origin configuration",
        "risk": "medium",
        "checks": ["origin allowlist", "credentialed requests", "preflight", "wildcard behavior"],
    },
    "api-security": {
        "name": "API security",
        "risk": "high",
        "checks": ["schema validation", "mass assignment", "rate limits", "method access", "GraphQL depth", "BOLA", "BFLA"],
    },
    "file-upload": {
        "name": "File upload and download",
        "risk": "high",
        "checks": ["type allowlist", "extension and MIME", "content validation", "storage separation", "download authorization"],
    },
    "race-condition": {
        "name": "Race conditions",
        "risk": "medium",
        "checks": ["coupons", "payments", "inventory", "withdrawals", "duplicate records", "account limits"],
    },
    "business-logic": {
        "name": "Business logic",
        "risk": "high",
        "checks": ["state transitions", "workflow order", "price/quantity rules", "privilege assumptions", "limits"],
    },
    "misconfiguration": {
        "name": "Security misconfiguration",
        "risk": "high",
        "checks": ["debug output", "directory exposure", "default accounts", "cloud storage", "headers", "TLS"],
    },
    "information-disclosure": {
        "name": "Information disclosure",
        "risk": "medium",
        "checks": ["error details", "metadata", "cache", "backups", "logs", "source maps", "archived endpoints"],
    },
    "supply-chain": {
        "name": "Dependency and supply-chain security",
        "risk": "high",
        "checks": ["known vulnerabilities", "component provenance", "dependency confusion", "build artifacts", "SBOM"],
    },
}


def test_categories() -> list[dict]:
    return [{"id": key, **value} for key, value in BUG_TEST_TYPES.items()]
