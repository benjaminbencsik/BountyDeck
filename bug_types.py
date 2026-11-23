BUG_TEST_TYPES = {
    "broken-access-control": {"name": "Broken access control / IDOR", "risk": "high", "phase": "manual", "checks": ["object ownership", "role boundaries", "horizontal authorization", "vertical authorization", "direct object references"]},
    "authentication": {"name": "Authentication and session security", "risk": "high", "phase": "manual", "checks": ["password policy", "session lifecycle", "logout", "MFA", "credential recovery", "account lockout"]},
    "injection": {"name": "Injection", "risk": "critical", "phase": "manual", "checks": ["SQL", "NoSQL", "command", "LDAP", "template", "header", "log injection"]},
    "xss": {"name": "Cross-site scripting", "risk": "high", "phase": "manual", "checks": ["stored context", "reflected context", "DOM context", "sanitization", "CSP"]},
    "ssrf": {"name": "Server-side request forgery", "risk": "critical", "phase": "manual", "checks": ["URL import", "webhook", "metadata destinations", "redirects", "internal network reachability"]},
    "csrf": {"name": "Cross-site request forgery", "risk": "medium", "phase": "manual", "checks": ["state-changing forms", "origin", "token binding", "cookie settings", "same-site policy"]},
    "open-redirect": {"name": "Open redirect", "risk": "medium", "phase": "manual", "checks": ["redirect parameters", "allowlisted destinations", "protocol confusion", "authentication flows"]},
    "cors": {"name": "CORS and cross-origin configuration", "risk": "medium", "phase": "manual", "checks": ["origin allowlist", "credentialed requests", "preflight", "wildcard behavior"]},
    "api-security": {"name": "API security", "risk": "high", "phase": "manual", "checks": ["schema validation", "mass assignment", "rate limits", "method access", "GraphQL depth", "BOLA", "BFLA"]},
    "file-upload": {"name": "File upload and download", "risk": "high", "phase": "manual", "checks": ["type allowlist", "extension and MIME", "content validation", "storage separation", "download authorization"]},
    "race-condition": {"name": "Race conditions", "risk": "medium", "phase": "manual", "checks": ["coupons", "payments", "inventory", "withdrawals", "duplicate records", "account limits"]},
    "business-logic": {"name": "Business logic", "risk": "high", "phase": "manual", "checks": ["state transitions", "workflow order", "price/quantity rules", "privilege assumptions", "limits"]},
    "misconfiguration": {"name": "Security misconfiguration", "risk": "high", "phase": "passive", "checks": ["debug output", "directory exposure", "default accounts", "cloud storage", "headers", "TLS"]},
    "information-disclosure": {"name": "Information disclosure", "risk": "medium", "phase": "manual", "checks": ["error details", "metadata", "cache", "backups", "logs", "source maps", "archived endpoints"]},
    "supply-chain": {"name": "Dependency and supply-chain security", "risk": "high", "phase": "manual", "checks": ["known vulnerabilities", "component provenance", "dependency confusion", "build artifacts", "SBOM"]},
    "deserialization": {"name": "Unsafe deserialization", "risk": "critical", "phase": "manual", "checks": ["JSON/XML/pickle/native parsing", "type allowlists", "object construction", "gadget reachability"]},
    "oauth-oidc": {"name": "OAuth and OIDC security", "risk": "high", "phase": "manual", "checks": ["state", "nonce", "PKCE", "redirect URI", "audience", "issuer", "token storage", "account linking"]},
    "websocket": {"name": "WebSocket security", "risk": "high", "phase": "manual", "checks": ["origin validation", "authentication", "authorization", "message authorization", "subscription isolation"]},
    "graphql": {"name": "GraphQL security", "risk": "high", "phase": "manual", "checks": ["field authorization", "introspection", "query depth", "complexity", "batching", "subscription authorization"]},
    "cache-poisoning": {"name": "Web cache poisoning", "risk": "high", "phase": "manual", "checks": ["key normalization", "unkeyed headers", "host handling", "multiple cache layers", "poisoned fallback"]},
    "request-smuggling": {"name": "HTTP request smuggling", "risk": "critical", "phase": "intrusive", "checks": ["front-end/back-end parsing", "CL/TE behavior", "TE/CL behavior", "desync isolation"]},
    "cache-deception": {"name": "Web cache deception", "risk": "high", "phase": "manual", "checks": ["sensitive path caching", "path normalization", "status code caching", "authenticated resources"]},
    "jwt": {"name": "JWT implementation security", "risk": "high", "phase": "manual", "checks": ["algorithm confusion", "signature", "audience", "issuer", "expiration", "key rotation", "jku/jwk handling"]},
    "secrets": {"name": "Exposed secrets", "risk": "high", "phase": "passive", "checks": ["repository/public assets", "JavaScript", "mobile bundles", "backup files", "logs", "credential false-positive review"]},
    "cloud-storage": {"name": "Cloud storage access", "risk": "high", "phase": "passive", "checks": ["bucket/container listing", "anonymous read", "anonymous write", "object ACL", "signed URL scope"]},
}


def test_categories() -> list[dict]:
    return [{"id": key, **value} for key, value in BUG_TEST_TYPES.items()]
