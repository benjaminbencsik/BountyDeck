# BountyDeck

BountyDeck is a bug-bounty reconnaissance workspace inspired by reNgine. It is intended to organize authorized assessments, asset discovery, endpoint and screenshot collection, vulnerability findings, scan configuration, and reporting.

## Scope and safety

Use BountyDeck only for targets covered by a written authorization or an applicable bug-bounty program scope. Do not target out-of-scope systems, bypass authorization controls, or perform intrusive actions without permission.

## Planned features

- Project and target management
- Scope-aware subdomain discovery
- DNS and HTTP asset inventory
- Port and service discovery
- Endpoint discovery and crawling
- Directory and file discovery
- Screenshot capture
- WHOIS and WAF information
- Open-source intelligence collection
- Nuclei-based vulnerability scanning
- Cloud and S3 misconfiguration checks
- Continuous monitoring and scheduled scans
- HackerOne-style and CSV scope imports
- Findings, evidence, filtering, and reporting dashboards
- YAML-based scan profiles and tool configuration

## Integrated tool categories

- Subdomain and DNS: Subfinder, Amass, Assetfinder, DNSx
- HTTP discovery: HTTPx
- Crawling: Katana, Waybackurls
- Ports: Naabu, Nmap
- Web probing: ffuf, Dirsearch
- Screenshots: Gowitness, Aquatone
- Vulnerability scanning: Nuclei
- OSINT and metadata: Whois, Shodan-compatible integrations
- Cloud storage checks: dedicated bucket scanners

Exact implementations and third-party tool versions will be documented before each integration is enabled.
