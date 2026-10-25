"""Semgrep: static analysis of first-party code (sast), plus a few Dockerfile rules."""

from riskgraph.modules.scanners.semgrep.adapter import SemgrepScanner

__all__ = ["SemgrepScanner"]
