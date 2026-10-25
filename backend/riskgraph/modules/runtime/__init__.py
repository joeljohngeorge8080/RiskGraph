"""Runtime: container images and language runtimes a repository declares (expansion X2).

Image references (Dockerfile, Compose, Kubernetes), runtime declarations, and their
end-of-life status from endoflife.date (refreshed by Beat, never on the scan path).
"""

from riskgraph.modules.runtime.declarations import RuntimeDecl, declarations
from riskgraph.modules.runtime.eol import (
    PRODUCTS,
    RUNTIME_ANALYZER,
    EolCycle,
    EolStatus,
    eol_status,
    parse_cycles,
    runtime_findings,
)
from riskgraph.modules.runtime.images import (
    ALLOWED_REGISTRIES,
    ImageRef,
    dockerfile_refs,
    image_refs,
    parse_ref,
)
from riskgraph.modules.runtime.models import RuntimeEol
from riskgraph.modules.runtime.service import load_feeds, refresh_eol, store_cycles

__all__ = [
    "ALLOWED_REGISTRIES",
    "PRODUCTS",
    "RUNTIME_ANALYZER",
    "EolCycle",
    "EolStatus",
    "ImageRef",
    "RuntimeDecl",
    "RuntimeEol",
    "declarations",
    "dockerfile_refs",
    "eol_status",
    "image_refs",
    "load_feeds",
    "parse_cycles",
    "parse_ref",
    "refresh_eol",
    "runtime_findings",
    "store_cycles",
]
