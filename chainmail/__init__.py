"""chainmail - graph-based Linux local privilege escalation path finder.

chainmail connects to a target over SSH, performs read-only enumeration,
models the host as a graph of principals (users/groups) and assets
(files/binaries/services/jobs), and finds multi-step escalation chains to
root that flat scanners like linpeas tend to miss.

It NEVER executes escalation on the target. For every chain it finds it
prints the manual proof-of-concept commands an operator can run to verify
the vector themselves.
"""

__version__ = "0.1.0"
__all__ = ["__version__"]
