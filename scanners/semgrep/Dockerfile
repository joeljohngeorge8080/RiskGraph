# riskgraph/scanner-semgrep. Rules are vendored at build time (never fetched at scan time).
ARG SEMGREP_VERSION
ARG SEMGREP_RULES_COMMIT
FROM python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS build
ARG SEMGREP_VERSION
ARG SEMGREP_RULES_COMMIT
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv && /opt/venv/bin/pip install "semgrep==${SEMGREP_VERSION}"
RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
# Same policy as infrastructure/scripts/install-scanners.sh: the registry pack, else the
# security rules of semgrep/semgrep-rules at the pinned commit.
RUN set -eux; \
    mkdir -p /opt/scanners/semgrep-rules; \
    if curl -fsSL --retry 2 -m 60 -o /opt/scanners/semgrep-rules/default.yml "https://semgrep.dev/c/p/default"; then \
      echo "rules: registry p/default"; \
    else \
      rm -f /opt/scanners/semgrep-rules/default.yml; \
      git -c advice.detachedHead=false clone --quiet --filter=blob:none --no-checkout \
        https://github.com/semgrep/semgrep-rules /tmp/rules; \
      git -C /tmp/rules checkout --quiet "${SEMGREP_RULES_COMMIT}"; \
      cd /tmp/rules; \
      for lang in python javascript typescript java go ruby php csharp dockerfile; do \
        [ -d "$lang" ] || continue; \
        find "$lang" -path '*/security/*' -name '*.yaml' ! -name '*.test.yaml' ! -name '*.fixed.*' \
          -exec cp --parents {} /opt/scanners/semgrep-rules/ \;; \
      done; \
      rm -rf /tmp/rules; \
    fi

FROM python@sha256:6a0e06f5ba0b373d051aabd3fffb9b873f27f9a2a3a14bcbe37dee6f0e3bbc70 AS runtime
COPY --from=build /opt/venv /opt/venv
COPY --from=build /opt/scanners/semgrep-rules /opt/scanners/semgrep-rules
ENV PATH=/opt/venv/bin:$PATH PYTHONDONTWRITEBYTECODE=1
USER 65534:65534
