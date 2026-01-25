#!/usr/bin/env bash
# Refresh the two public enrichment feeds. Both are free and need no account.
set -euo pipefail
cd "$(dirname "$0")/.."
curl -sSL -o data/feeds/kev.json "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
curl -sSL -o data/feeds/epss.csv.gz "https://epss.cyentia.com/epss_scores-current.csv.gz"
echo "KEV: $(jq -r '.catalogVersion + " (" + (.count|tostring) + " CVEs)"' data/feeds/kev.json)"
echo "EPSS: $(zcat data/feeds/epss.csv.gz | head -1)"
