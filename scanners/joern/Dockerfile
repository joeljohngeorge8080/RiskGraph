# riskgraph/scanner-joern (X4 part 2, ADR-0025): Joern with RiskGraph's tier-2 taint query.
# Upstream publishes no release tags, only the moving `master` and `nightly`, so the base is
# pinned by the linux/amd64 digest measured in the spike (docs/auto/spikes/joern/RESULT.md).
# The build checks that the pinned image really is JOERN_VERSION and records it for
# `version_argv`.
ARG JOERN_VERSION
FROM ghcr.io/joernio/joern@sha256:f6b35cd1296f92070305fcc7cbdb2f113d26ea1920abcb303e1a6622c6b1ba2a
ARG JOERN_VERSION
COPY taint.sc /opt/riskgraph/joern/taint.sc
RUN set -eu; \
    found="$(ls /opt/joern/joern-cli/lib | sed -n 's/^io\.joern\.joern-cli-\(.*\)\.jar$/\1/p')"; \
    test "${found}" = "${JOERN_VERSION}" || { echo "base image is joern ${found}, expected ${JOERN_VERSION}"; exit 1; }; \
    echo "${JOERN_VERSION}" > /opt/riskgraph/joern/VERSION; \
    chmod -R a+rX /opt/riskgraph
USER 65534:65534
