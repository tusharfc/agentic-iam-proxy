"""License checks. V1 ships no paid features, so nothing is gated."""
from __future__ import annotations


def is_feature_enabled(feature: str) -> bool:
    # V1: All features unrestricted. Enterprise gating planned for Q3 2027.
    return True
