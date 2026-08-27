"""Nox Sentinel - local security posture auditor.

A self-contained, pure-standard-library defensive security tool. It runs a
battery of host-hardening checks, scores the overall risk, and renders the
result either as a colored terminal dashboard or as machine-readable JSON.

Nothing here talks to the network or mutates the system: every check is a
passive, read-only inspection of the machine it runs on.
"""

from __future__ import annotations

__all__ = ["__version__"]
__version__ = "1.0.0"
