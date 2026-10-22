# riskgraph/scanner-syft. Syft inventories packages; its CycloneDX output feeds the SBOM.
ARG SYFT_VERSION
FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS fetch
ARG SYFT_VERSION
ARG TARGETARCH
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates curl \
    && rm -rf /var/lib/apt/lists/*
RUN set -eux; \
    case "${TARGETARCH:-amd64}" in amd64) arch=amd64 ;; arm64) arch=arm64 ;; *) exit 1 ;; esac; \
    base="https://github.com/anchore/syft/releases/download/v${SYFT_VERSION}"; \
    asset="syft_${SYFT_VERSION}_linux_${arch}.tar.gz"; \
    mkdir /dl; cd /dl; \
    curl -fsSL --retry 3 -o "$asset" "$base/$asset"; \
    curl -fsSL --retry 3 -o checksums.txt "$base/syft_${SYFT_VERSION}_checksums.txt"; \
    grep " $asset\$" checksums.txt | sha256sum -c -; \
    tar -xzf "$asset" -C /dl syft

FROM debian@sha256:7ff6ba31527b9e336162fa061746c366c4b2032f4d2cff2078bea43f78efe3f8 AS runtime
COPY --from=fetch /dl/syft /usr/local/bin/syft
USER 65534:65534
