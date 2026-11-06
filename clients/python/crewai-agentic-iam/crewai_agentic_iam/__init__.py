from __future__ import annotations

from typing import Any

from crewai_agentic_iam.wrapper import SecureAPIWrapper

__all__ = ["SecureAPIWrapper", "SecureCrewAITool"]
__version__ = "0.1.0"


def __getattr__(name: str) -> Any:
    # Importing crewai takes seconds; load it only when the tool class is used.
    if name == "SecureCrewAITool":
        from crewai_agentic_iam.tools import SecureCrewAITool

        return SecureCrewAITool
    raise AttributeError(f"module {__name__!r} has no attribute {name!r}")
