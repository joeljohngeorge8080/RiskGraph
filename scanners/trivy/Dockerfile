# riskgraph/scanner-trivy. The binary is checksum-verified against the release file.
# Runs with --network none: the vulnerability DB comes from the trusted refresh job,
# which writes the shared cache volume (blueprint §9.2, §9.3).
ARG TRIVY_VERSION
FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS fetch
ARG TRIVY_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=64bit ;; arm64) arch=ARM64 ;; *) exit 1 ;; esac; \
    base="https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}"; \
    asset="trivy_${TRIVY_VERSION}_Linux-${arch}.tar.gz"; \
    mkdir /dl; cd /dl; \
    curl -fsSL --retry 3 -o "$asset" "$base/$asset"; \
    curl -fsSL --retry 3 -o checksums.txt "$base/trivy_${TRIVY_VERSION}_checksums.txt"; \
    grep " $asset\$" checksums.txt | sha256sum -c -; \
    tar -xzf "$asset" -C /dl trivy

FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
# The DB refresh is the only egress use: it needs a CA bundle to verify the registry.
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=fetch /dl/trivy /usr/local/bin/trivy
USER 65534:65534
