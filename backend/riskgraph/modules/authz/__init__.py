"""Authorization: route inventory, guards and (from X5 part 2) authz findings (plan §3.B).

Input is the reachability extractor's ``http`` sections; output is ``route`` and
``auth_guard`` evidence. Assurance is honest: a route we parsed is verified, a guard is
at most inferred, and an unknown framework is never reported as "no guard" (ADR-0022).
"""

from riskgraph.modules.authz.analysis import RULES, AuthzIssue, AuthzResult, analyze, resource
from riskgraph.modules.authz.guards import Catalogue, load_catalogue
from riskgraph.modules.authz.inventory import STATUSES, Guard, Route, route_inventory
from riskgraph.modules.authz.service import PRODUCER, list_routes, route_evidence, summary

__all__ = [
    "PRODUCER",
    "RULES",
    "STATUSES",
    "AuthzIssue",
    "AuthzResult",
    "Catalogue",
    "Guard",
    "Route",
    "analyze",
    "list_routes",
    "load_catalogue",
    "resource",
    "route_evidence",
    "route_inventory",
    "summary",
]
