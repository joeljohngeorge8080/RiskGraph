"""Trivy: dependency CVEs (sca), secrets and IaC misconfigurations."""

from riskgraph.modules.scanners.trivy.adapter import TrivyScanner

__all__ = ["TrivyScanner"]
