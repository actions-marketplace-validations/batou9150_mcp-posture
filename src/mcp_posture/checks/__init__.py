"""Check modules. Importing this package registers every check in the catalogue."""

from mcp_posture.checks import asm, authn, cimd, prm, trn

__all__ = ["asm", "authn", "cimd", "prm", "trn"]
