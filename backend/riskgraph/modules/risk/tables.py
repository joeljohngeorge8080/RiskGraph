"""Factor tables for risk model v1-cf (blueprint §14.2, context-free MVP variant)."""

from __future__ import annotations

from riskgraph.shared.vocabulary import Priority, Severity

MODEL_VERSION = "v1-cf.1"
FLOOR = 0.05

# Context the MVP cannot observe yet: blueprint "unknown" defaults (§14.2, §14.3).
UNKNOWN_EXPOSURE = 0.5  # X
UNKNOWN_REACHABILITY = 0.6  # R
UNKNOWN_DATA = 0.5  # D
UNKNOWN_PRIVILEGE = 0.5  # P
DEFAULT_CRITICALITY = 0.5  # C

# Exploitability E when a CVE has neither KEV nor EPSS nor a CVSS vector.
E_BY_SEVERITY = {
    Severity.CRITICAL: 0.6,
    Severity.HIGH: 0.45,
    Severity.MEDIUM: 0.3,
    Severity.LOW: 0.15,
    Severity.INFO: FLOOR,
}
# Technical impact T when a CVE has no CVSS vector.
T_BY_SEVERITY = {
    Severity.CRITICAL: 0.9,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.5,
    Severity.LOW: 0.3,
    Severity.INFO: 0.1,
}

E_SECRET_LIVE = 0.9
E_SECRET_GENERIC = 0.6
T_SECRET = 1.0

E_SAST = {
    Severity.CRITICAL: 0.7,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.2,
    Severity.INFO: 0.2,
}
E_SAST_HIGH_CONFIDENCE_BONUS = 0.1
T_SAST = {
    "command_injection": 0.9,
    "code_injection": 0.9,
    "deserialization": 0.9,
    "sql_injection": 0.9,
    "injection": 0.9,
    "ssrf": 0.9,
    "xxe": 0.8,
    "path_traversal": 0.8,
    "auth": 0.8,
    "hardcoded_secret": 0.8,
    "privilege": 0.6,
    "xss": 0.6,
    "open_redirect": 0.4,
    "crypto": 0.4,
    "info_leak": 0.4,
    "other": 0.2,
}

E_IAC = {
    "public": 0.6,
    "secrets": 0.6,
    "iam": 0.5,
    "encryption": 0.25,
    "logging": 0.25,
    "hygiene": 0.25,
}
T_IAC = {
    "public": 0.9,
    "secrets": 0.9,
    "iam": 0.8,
    "encryption": 0.5,
    "logging": 0.3,
    "hygiene": 0.2,
}

# Corroboration K: +5% per additional agreeing scanner, at most +10%.
K_PER_EXTRA_SCANNER = 0.05
K_MAX_EXTRA = 2

# Priority bands on the 0-100 score (blueprint §14.2; calibrated in Phase 17).
BANDS = ((70.0, Priority.CRITICAL), (45.0, Priority.HIGH), (20.0, Priority.MEDIUM))
