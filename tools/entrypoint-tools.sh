#!/usr/bin/env bash
set -Eeuo pipefail

MODE="${1:-install}"
TOOLS_DIR="/opt/bountydeck/tools"
mkdir -p "$TOOLS_DIR/bin"

case "$MODE" in
  install|update)
    cp -a /usr/local/bin/{subfinder,dnsx,httpx,naabu,katana,nuclei,amass,assetfinder,gau,waybackurls,gowitness} "$TOOLS_DIR/bin/" 2>/dev/null || true
    cp -a /usr/bin/{nmap,whois,dig,ffuf} "$TOOLS_DIR/bin/" 2>/dev/null || true
    ln -sfn /opt/dirsearch/bin/dirsearch "$TOOLS_DIR/bin/dirsearch"

    if [[ "$MODE" == "update" ]]; then
      export GOBIN="$TOOLS_DIR/bin"
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/subfinder/v2/cmd/subfinder@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/dnsx/cmd/dnsx@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/httpx/cmd/httpx@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/naabu/v2/cmd/naabu@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/katana/cmd/katana@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/owasp-amass/amass/v4/...@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/tomnomnom/assetfinder@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/lc/gau/v2/cmd/gau@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/tomnomnom/waybackurls@latest
      /usr/local/go/bin/go install -ldflags="-s -w" github.com/sensepost/gowitness@latest
      /opt/dirsearch/bin/pip install --upgrade --no-cache-dir dirsearch
    fi

    if command -v nuclei >/dev/null; then
      nuclei -update-templates >/dev/null 2>&1 || true
    fi

    cp /opt/bountydeck/tool-registry.json "$TOOLS_DIR/registry.json"
    printf 'BountyDeck tools %s complete in %s\n' "$MODE" "$TOOLS_DIR"
    ;;
  status)
    cat "$TOOLS_DIR/registry.json"
    ;;
  shell)
    exec /bin/bash
    ;;
  *)
    echo "Usage: bountydeck-tools [install|update|status|shell]" >&2
    exit 2
    ;;
esac
