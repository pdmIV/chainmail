"""Startup ASCII banner for the chainmail CLI."""
from __future__ import annotations

# figlet "slant" rendering of "chainmail"
BANNER = r"""
        __          _                       _ __
  _____/ /_  ____ _(_)___  ____ ___  ____ _(_) /
 / ___/ __ \/ __ `/ / __ \/ __ `__ \/ __ `/ / /
/ /__/ / / / /_/ / / / / / / / / / / /_/ / / /
\___/_/ /_/\__,_/_/_/ /_/_/ /_/ /_/\__,_/_/_/
"""

TAGLINE = "graph-based Linux privilege-escalation path finder"
CREDIT = "by @pdmIV (GitHub) · watchfuleye (HTB)"


def render(version: str, color: bool = True) -> str:
    art = BANNER.strip("\n")
    tagline = f"  {TAGLINE}  —  v{version}"
    credit = f"  {CREDIT}"
    if color:
        cyan, bold, dim, reset = "\033[36m", "\033[1m", "\033[2m", "\033[0m"
        art = f"{bold}{cyan}{art}{reset}"
        tagline = f"{cyan}{tagline}{reset}"
        credit = f"{dim}{credit}{reset}"
    return f"{art}\n{tagline}\n{credit}\n"
