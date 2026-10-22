#!/usr/bin/env bash
# Install the four MVP scanners into PREFIX (ADR-0009).
#
#   PREFIX/bin/{trivy,gitleaks,semgrep,checkov}
#   PREFIX/tools/          uv tool venvs for semgrep and checkov (isolated from the app venv)
#   PREFIX/semgrep-rules/  vendored rule set, so semgrep needs no network at scan time
#
# Release tarballs are verified against the upstream checksums file before extraction.
# Used by docker/backend.Dockerfile (worker target) and `make scanner-tools`.
set -euo pipefail

PREFIX="${1:?usage: install-scanners.sh PREFIX}"
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
# shellcheck source=/dev/null
source "${HERE}/../../docker/scanner-versions.env"

mkdir -p "${PREFIX}/bin" "${PREFIX}/tools"
PREFIX="$(cd "${PREFIX}" && pwd)"
WORK="$(mktemp -d)"
trap 'rm -rf "${WORK}"' EXIT

case "$(uname -m)" in
  x86_64 | amd64) TRIVY_ARCH="64bit"; GITLEAKS_ARCH="x64" ;;
  aarch64 | arm64) TRIVY_ARCH="ARM64"; GITLEAKS_ARCH="arm64" ;;
  *) echo "unsupported architecture: $(uname -m)" >&2; exit 1 ;;
esac

fetch_verified() {
  # fetch_verified <dir> <base-url> <asset> <checksums-file>
  local dir="$1" base="$2" asset="$3" sums="$4"
  mkdir -p "${dir}"
  curl -fsSL --retry 3 -o "${dir}/${asset}" "${base}/${asset}"
  curl -fsSL --retry 3 -o "${dir}/${sums}" "${base}/${sums}"
  (cd "${dir}" && grep " ${asset}\$" "${sums}" | sha256sum -c -)
}

# --- trivy ---------------------------------------------------------------------------
asset="trivy_${TRIVY_VERSION}_Linux-${TRIVY_ARCH}.tar.gz"
fetch_verified "${WORK}/trivy" \
  "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}" \
  "${asset}" "trivy_${TRIVY_VERSION}_checksums.txt"
mkdir -p "${WORK}/trivy/x"
tar -xzf "${WORK}/trivy/${asset}" -C "${WORK}/trivy/x" trivy
install -m 0755 "${WORK}/trivy/x/trivy" "${PREFIX}/bin/trivy"

# --- gitleaks ------------------------------------------------------------------------
asset="gitleaks_${GITLEAKS_VERSION}_linux_${GITLEAKS_ARCH}.tar.gz"
fetch_verified "${WORK}/gitleaks" \
  "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}" \
  "${asset}" "gitleaks_${GITLEAKS_VERSION}_checksums.txt"
mkdir -p "${WORK}/gitleaks/x"
tar -xzf "${WORK}/gitleaks/${asset}" -C "${WORK}/gitleaks/x" gitleaks
install -m 0755 "${WORK}/gitleaks/x/gitleaks" "${PREFIX}/bin/gitleaks"

# --- semgrep and checkov (PyPI, one isolated venv each) ------------------------------
export UV_TOOL_DIR="${PREFIX}/tools" UV_TOOL_BIN_DIR="${PREFIX}/bin"
PY="${SCANNER_PYTHON:-python3}"
uv tool install --force --python "${PY}" "semgrep==${SEMGREP_VERSION}"
uv tool install --force --python "${PY}" "checkov==${CHECKOV_VERSION}"

# --- semgrep rules -------------------------------------------------------------------
# Prefer the registry pack; fall back to the security rules of semgrep/semgrep-rules at a
# pinned commit when semgrep.dev is unreachable. Rules are never committed to this repo.
RULES="${PREFIX}/semgrep-rules"
rm -rf "${RULES}" && mkdir -p "${RULES}"
if curl -fsSL --retry 2 -m 60 -o "${RULES}/default.yml" "https://semgrep.dev/c/p/default"; then
  echo "semgrep rules: registry p/default"
else
  rm -f "${RULES}/default.yml"
  git -c advice.detachedHead=false clone --quiet --filter=blob:none --no-checkout \
    https://github.com/semgrep/semgrep-rules "${WORK}/semgrep-rules"
  git -C "${WORK}/semgrep-rules" checkout --quiet "${SEMGREP_RULES_COMMIT}"
  (
    cd "${WORK}/semgrep-rules"
    for lang in python javascript typescript java go ruby php csharp dockerfile; do
      [ -d "${lang}" ] || continue
      find "${lang}" -path '*/security/*' -name '*.yaml' ! -name '*.test.yaml' ! -name '*.fixed.*' \
        -exec cp --parents {} "${RULES}/" \;
    done
  )
  echo "semgrep rules: semgrep-rules@${SEMGREP_RULES_COMMIT} ($(find "${RULES}" -name '*.yaml' | wc -l) files)"
fi

"${PREFIX}/bin/trivy" --version | head -1
"${PREFIX}/bin/gitleaks" version
"${PREFIX}/bin/semgrep" --version
"${PREFIX}/bin/checkov" --version
