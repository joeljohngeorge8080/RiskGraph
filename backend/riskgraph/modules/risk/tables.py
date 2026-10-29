"""Factor tables for risk model v1-ctx (blueprint §14.2).

v1-ctx.1 added deployment context (X, D, P, C) to v1-cf.1. v1-ctx.2 adds reachability
(R from L0/L1/L2), attack-path effective impact (§14.4) and the "L0 with high confidence
→ ceiling Medium" rule (§14.5). Without context, reachability and paths, all three
versions give identical scores. v1-ctx.3 (expansion X1, X2): effective impact only from
paths of at least "inferred" assurance (ADR-0017), and an interim score for runtime
end-of-life findings until risk v2 (X6) defines runtime factor tables (ADR-0018).
v1-ctx.4 (X5): authorization findings get interim factors from the SAST rows for a
missing-authorization weakness and stay at Low until risk v2 (X6) defines their tables
(ADR-0023). Scores of every other finding are unchanged.
v2.1 (X6, ADR-0024): factor tables for image packages (R not assessable), tier-1 taint
flows (E by CWE and rule confidence), runtime end-of-life (E by time past the end of
support) and inferred authorization findings (no interim cap; a hypothesis stays Low).
Without these inputs, v2.1 scores equal v1-ctx.3.
"""

from __future__ import annotations

from riskgraph.shared.vocabulary import Priority, Severity

MODEL_VERSION = "v2.1"
FLOOR = 0.05

# "Unknown" defaults when no context source covers a finding (§14.2, §14.3).
UNKNOWN_EXPOSURE = 0.5  # X
UNKNOWN_REACHABILITY = 0.6  # R when reachability is unknown
UNKNOWN_DATA = 0.5  # D
UNKNOWN_PRIVILEGE = 0.5  # P
DEFAULT_CRITICALITY = 0.5  # C

# Context values (§14.2), keyed by the labels the context module produces.
X_VALUES = {"internet_noauth": 1.0, "internet_auth": 0.7, "internal": 0.4, "isolated": 0.15}
D_VALUES = {
    "credentials": 1.0,
    "financial": 0.9,
    "pii": 0.9,
    "confidential": 0.7,
    "internal": 0.4,
    "public": 0.1,
}
P_VALUES = {"admin": 1.0, "elevated": 0.8, "limited": 0.5, "read_only": 0.3}
C_VALUES = {"high": 0.9, "medium": 0.5, "low": 0.2}
R_VALUES = {"L3": 1.0, "L2": 0.8, "L1": 0.5, "L0": 0.1}

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

# Runtime end-of-life (ADR-0024; ADR-0018's interim E 0.5, T 0.6 before). An unsupported
# release gets no security fixes, so advisories against it pile up unpatched: E grows with
# the time past the end of support, read from the feed's date and the feed's snapshot time
# (never the clock). Without a date (an OS flag, a feed giving true/false) E stays 0.5.
E_RUNTIME_EOL = 0.5
E_RUNTIME_EOL_BY_AGE = ((3 * 365, 0.6), (365, 0.5), (0, 0.4))  # (at least days, E)
T_RUNTIME_EOL = 0.6

# Packages installed in a container image (X2): the code that uses them is not analysed,
# so reachability is "not assessable" (plan X6 row), slightly below the unknown 0.6 of a
# repository dependency whose analysis simply did not cover it.
R_NOT_ASSESSABLE = 0.5

# Tier-1 taint (ADR-0024): a flow traced from an HTTP source to the sink shows that the
# attacker controls the argument, which a pattern match only suggests. E by the CWE class
# and the rule's confidence; it only ever raises the SAST row (E = max). Injection into a
# query or a shell is directly exploitable; deserialization needs a gadget chain; path
# traversal and SSRF need a useful file or endpoint behind them. A MEDIUM-confidence rule
# (sanitizer coverage less certain) is 0.1 lower; a LOW-confidence one adds nothing.
E_TAINT = {
    "CWE-89": {"HIGH": 0.85, "MEDIUM": 0.75},
    "CWE-78": {"HIGH": 0.85, "MEDIUM": 0.75},
    "CWE-502": {"HIGH": 0.8, "MEDIUM": 0.7},
    "CWE-22": {"HIGH": 0.75, "MEDIUM": 0.65},
    "CWE-918": {"HIGH": 0.75, "MEDIUM": 0.65},
}

# Authorization findings (ADR-0024, replacing ADR-0023's interim cap). An unguarded route
# needs nothing but a request, but "no guard" is inferred from a catalogue that can miss a
# custom guard, so E sits under the SAST row of the same severity (0.1 for High and
# Medium, 0.05 for Low). T is the SAST "auth" row. A hypothesis (BOLA) is capped just
# under Medium, priority Low.
AUTHZ_CATEGORY = "auth"
AUTHZ_SCORE_CEILING = 19.99

E_SAST = {
    Severity.CRITICAL: 0.7,
    Severity.HIGH: 0.7,
    Severity.MEDIUM: 0.45,
    Severity.LOW: 0.2,
    Severity.INFO: 0.2,
}
E_SAST_HIGH_CONFIDENCE_BONUS = 0.1
E_AUTHZ_INFERRED = {
    Severity.CRITICAL: 0.6,
    Severity.HIGH: 0.6,
    Severity.MEDIUM: 0.35,
    Severity.LOW: 0.15,
    Severity.INFO: 0.15,
}
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
