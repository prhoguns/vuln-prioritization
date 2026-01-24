#!/usr/bin/env bash
# Scan a set of container images with Trivy and keep the JSON. Images chosen to span "old and unpatched"
# through "current": the same base with years between them shows what patching actually buys.
set -euo pipefail
cd "$(dirname "$0")/.."
IMAGES=(
  nginx:1.18            # 2020
  nginx:1.27            # current
  python:3.8-slim       # older interpreter
  python:3.12-slim      # current
  node:14               # EOL runtime
  node:22-slim          # current
  postgres:11           # EOL database
  postgres:16           # current
  ubuntu:20.04          # LTS, still supported
  alpine:3.20           # minimal
)
mkdir -p data/scans
for img in "${IMAGES[@]}"; do
  out="data/scans/$(echo "$img" | tr '/:' '__').json"
  echo "scanning $img -> $out"
  docker run --rm -v /var/run/docker.sock:/var/run/docker.sock -v trivy-cache:/root/.cache/ \
    aquasec/trivy:0.58.1 image --quiet --format json --scanners vuln --timeout 15m "$img" > "$out"
done
echo "done: $(ls data/scans | wc -l) scans"
