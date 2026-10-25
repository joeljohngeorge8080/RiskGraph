# riskgraph/scanner-gitleaks. Checksum-verified release binary; no network at scan time.
ARG GITLEAKS_VERSION
FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS fetch
ARG GITLEAKS_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=x64 ;; arm64) arch=arm64 ;; *) exit 1 ;; esac; \
    base="https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}"; \
    asset="gitleaks_${GITLEAKS_VERSION}_linux_${arch}.tar.gz"; \
    mkdir /dl; cd /dl; \
    curl -fsSL --retry 3 -o "$asset" "$base/$asset"; \
    curl -fsSL --retry 3 -o checksums.txt "$base/gitleaks_${GITLEAKS_VERSION}_checksums.txt"; \
    grep " $asset\$" checksums.txt | sha256sum -c -; \
    tar -xzf "$asset" -C /dl gitleaks

FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
COPY --from=fetch /dl/gitleaks /usr/local/bin/gitleaks
USER 65534:65534
