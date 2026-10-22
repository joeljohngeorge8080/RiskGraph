"""Curated cross-scanner equivalences used for merging (ADR-0010).

Merging is deliberately conservative: two results become one finding only when an
explicit table says they describe the same problem. A false merge hides a finding; a
missed merge only shows it twice.

- Secrets: rule IDs from Gitleaks and Trivy are grouped into credential *families*
  (aws, github, private_key, …). Same file + same family + overlapping lines → one.
- IaC: check IDs from Checkov, Trivy (misconfig) and a few Semgrep rules are grouped into
  *topics* (s3-public-access-block, sg-open-ingress, …). Same file + same topic + same
  resource → one. Unmapped checks never merge across scanners.
"""

from __future__ import annotations

import re
from enum import StrEnum

# --- secrets -------------------------------------------------------------------------

_SECRET_PREFIX_FAMILY = (
    ("aws-", "aws"),
    ("github-", "github"),
    ("gitlab-", "gitlab"),
    ("slack-", "slack"),
    ("stripe-", "stripe"),
    ("gcp-", "gcp"),
    ("google-", "gcp"),
    ("azure-", "azure"),
    ("private-key", "private_key"),
    ("openai-", "openai"),
    ("anthropic-", "anthropic"),
    ("npm-", "npm"),
    ("pypi-", "pypi"),
    ("twilio-", "twilio"),
    ("sendgrid-", "sendgrid"),
    ("jwt", "jwt"),
)

# Format-validated credential types that grant real access when leaked (blueprint §10.3).
LIVE_CREDENTIAL_RULES = frozenset(
    {
        # gitleaks
        "aws-access-token",
        "gcp-service-account",
        "github-pat",
        "github-fine-grained-pat",
        "github-oauth",
        "github-app-token",
        "gitlab-pat",
        "private-key",
        "slack-bot-token",
        "slack-user-token",
        "stripe-access-token",
        # trivy
        "aws-access-key-id",
        "aws-secret-access-key",
        "slack-access-token",
        "stripe-secret-token",
    }
)


SECRET_FAMILIES = frozenset({family for _, family in _SECRET_PREFIX_FAMILY} | {"generic"})


def secret_family(rule_id: str) -> str:
    rid = rule_id.lower()
    for prefix, family in _SECRET_PREFIX_FAMILY:
        if rid.startswith(prefix):
            return family
    return "generic"


# --- IaC -----------------------------------------------------------------------------


class IacFamily(StrEnum):
    PUBLIC = "public"
    IAM = "iam"
    SECRETS = "secrets"
    ENCRYPTION = "encryption"
    LOGGING = "logging"
    HYGIENE = "hygiene"


_TOPIC_MEMBERS: dict[str, tuple[IacFamily, tuple[str, ...]]] = {
    # AWS S3
    "s3-public-acl": (IacFamily.PUBLIC, ("CKV_AWS_20", "CKV_AWS_57", "AWS-0092")),
    "s3-public-access-block": (
        IacFamily.PUBLIC,
        (
            *("CKV2_AWS_6", "CKV_AWS_53", "CKV_AWS_54", "CKV_AWS_55", "CKV_AWS_56"),
            *("AWS-0086", "AWS-0087", "AWS-0091", "AWS-0093", "AWS-0094"),
        ),
    ),
    "s3-encryption": (IacFamily.ENCRYPTION, ("CKV_AWS_19", "AWS-0088")),
    "s3-encryption-cmk": (IacFamily.ENCRYPTION, ("CKV_AWS_145", "AWS-0132")),
    "s3-logging": (IacFamily.LOGGING, ("CKV_AWS_18", "AWS-0089")),
    "s3-versioning": (IacFamily.HYGIENE, ("CKV_AWS_21", "AWS-0090")),
    # AWS networking / compute
    "sg-open-ingress": (
        IacFamily.PUBLIC,
        ("CKV_AWS_24", "CKV_AWS_25", "CKV_AWS_260", "AWS-0107"),
    ),
    "sg-open-egress": (IacFamily.PUBLIC, ("CKV_AWS_382", "AWS-0104")),
    "sg-description": (IacFamily.HYGIENE, ("CKV_AWS_23", "AWS-0099", "AWS-0124")),
    "ec2-imdsv2": (IacFamily.IAM, ("CKV_AWS_79", "AWS-0028")),
    "ec2-public-ip": (IacFamily.PUBLIC, ("CKV_AWS_88", "AWS-0009")),
    "ebs-encryption": (IacFamily.ENCRYPTION, ("CKV_AWS_8", "AWS-0131")),
    "rds-encryption": (IacFamily.ENCRYPTION, ("CKV_AWS_16", "AWS-0080")),
    "rds-public": (IacFamily.PUBLIC, ("CKV_AWS_17", "AWS-0180")),
    # Dockerfile
    "dockerfile-root-user": (
        IacFamily.IAM,
        ("CKV_DOCKER_3", "DS-0002", "dockerfile.security.missing-user"),
    ),
    "dockerfile-healthcheck": (IacFamily.HYGIENE, ("CKV_DOCKER_2", "DS-0026")),
    "dockerfile-latest-tag": (IacFamily.HYGIENE, ("CKV_DOCKER_7", "DS-0001")),
    "dockerfile-ssh-port": (IacFamily.PUBLIC, ("CKV_DOCKER_1", "DS-0004")),
    "dockerfile-add": (IacFamily.HYGIENE, ("CKV_DOCKER_4", "DS-0005")),
    # Kubernetes
    "k8s-privileged": (IacFamily.IAM, ("CKV_K8S_16", "KSV-0017")),
    "k8s-privilege-escalation": (IacFamily.IAM, ("CKV_K8S_20", "KSV-0001")),
    "k8s-run-as-non-root": (IacFamily.IAM, ("CKV_K8S_23", "KSV-0012")),
    "k8s-read-only-root-fs": (IacFamily.HYGIENE, ("CKV_K8S_22", "KSV-0014")),
    "k8s-cpu-limits": (IacFamily.HYGIENE, ("CKV_K8S_11", "KSV-0011")),
    "k8s-memory-limits": (IacFamily.HYGIENE, ("CKV_K8S_13", "KSV-0018")),
    "k8s-host-network": (IacFamily.PUBLIC, ("CKV_K8S_19", "KSV-0009")),
    # Hard-coded cloud credentials in IaC
    "iac-hardcoded-credentials": (IacFamily.SECRETS, ("CKV_AWS_41", "CKV_AWS_46")),
}

IAC_TOPICS: dict[str, str] = {
    check: topic for topic, (_, checks) in _TOPIC_MEMBERS.items() for check in checks
}
_TOPIC_FAMILY = {topic: family for topic, (family, _) in _TOPIC_MEMBERS.items()}

_LEGACY_ID = re.compile(r"^(?:AVD-)?([A-Z]+[0-9]*?)-?(\d+)$")


def normalize_check_id(check_id: str) -> str:
    """Trivy has used ``AVD-AWS-0086``, ``AWS-0086`` and ``DS002`` for the same check."""
    cid = check_id.strip()
    m = _LEGACY_ID.match(cid.upper())
    if m and not cid.upper().startswith("CKV"):
        return f"{m.group(1)}-{int(m.group(2)):04d}"
    return cid


def iac_topic(check_id: str) -> str | None:
    return IAC_TOPICS.get(check_id)


_KEYWORDS: tuple[tuple[IacFamily, tuple[str, ...]], ...] = (
    (IacFamily.SECRETS, ("hard coded", "hardcoded", "secret", "password", "access key")),
    (IacFamily.PUBLIC, ("public", "0.0.0.0", "internet", "ingress", "unrestricted", "exposed")),
    (IacFamily.IAM, ("iam", "privilege", "root", "admin", "wildcard", "policy", "role")),
    (IacFamily.ENCRYPTION, ("encrypt", "kms", "tls", "ssl", "https")),
    (IacFamily.LOGGING, ("log", "monitor", "audit", "trail")),
)


def iac_family(topic: str | None, title: str) -> IacFamily:
    if topic is not None:
        return _TOPIC_FAMILY[topic]
    lowered = title.lower()
    for family, words in _KEYWORDS:
        if any(w in lowered for w in words):
            return family
    return IacFamily.HYGIENE
