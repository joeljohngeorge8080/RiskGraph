"""Syft: package inventory (CycloneDX). Its output is the SBOM, not a list of findings."""

from riskgraph.modules.scanners.syft.adapter import SyftScanner

__all__ = ["SyftScanner"]
