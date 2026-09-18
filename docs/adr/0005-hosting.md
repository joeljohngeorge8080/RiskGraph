# ADR-0005: Hosting and deployment

Status: accepted · Date: 2026-09-19

## Decision
Docker Compose with `dev`, `test` and `prod` profiles. Production is one Linux VM (the demo laptop, or an AWS EC2 `t3.medium`/`t3.large`) running Caddy (TLS), api, worker, beat, postgres, redis, docker-socket-proxy and optional ollama/observability profiles. Images built in CI and pushed to GHCR. Nightly `pg_dump`, optional S3 copy. No Kubernetes, no RDS, no Secrets Manager, no ECR.

## Alternatives considered
k3s (previous draft; rejected: ops surface with no demo value), ECS Fargate (rejected: cost and Docker-socket model incompatible with the scanner runner), PaaS (rejected: needs a Docker daemon for scanner containers).

## Consequences
- (−) single host, no HA; acceptable and stated in NFRs
- (→) trigger: multi-node scanning → `K8sJobRunner` behind the `ScannerRunner` seam
