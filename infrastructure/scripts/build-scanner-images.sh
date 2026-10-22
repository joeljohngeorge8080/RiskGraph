#!/usr/bin/env bash
# Build the hardened scanner images (blueprint §9.3, ADR-0014).
#
#   riskgraph/scanner-<name>:<version>   one per scanner, from scanners/<name>/Dockerfile
#   riskgraph/git-fetcher:bookworm       the only image used for a clone
#
# Versions come from docker/scanner-versions.env, the single source of truth. The adapters'
# image_tag constants must match it; backend/tests/test_scanner_images.py enforces that.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/../.." && pwd)"
# shellcheck source=/dev/null
source "${ROOT}/docker/scanner-versions.env"

build() {
  # build <name> <tag> <build-arg>...
  local name="$1" tag="$2"
  shift 2
  local args=()
  for a in "$@"; do args+=(--build-arg "$a"); done
  echo "==> riskgraph/${name}:${tag}"
  docker build --pull=false "${args[@]}" -t "riskgraph/${name}:${tag}" "${ROOT}/scanners/${name#scanner-}"
}

build scanner-trivy "${TRIVY_VERSION}" "TRIVY_VERSION=${TRIVY_VERSION}"
build scanner-gitleaks "${GITLEAKS_VERSION}" "GITLEAKS_VERSION=${GITLEAKS_VERSION}"
build scanner-syft "${SYFT_VERSION}" "SYFT_VERSION=${SYFT_VERSION}"
build scanner-semgrep "${SEMGREP_VERSION}" \
  "SEMGREP_VERSION=${SEMGREP_VERSION}" "SEMGREP_RULES_COMMIT=${SEMGREP_RULES_COMMIT}"
build scanner-checkov "${CHECKOV_VERSION}" "CHECKOV_VERSION=${CHECKOV_VERSION}"
build git-fetcher bookworm
