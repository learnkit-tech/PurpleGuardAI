"""Optional scanner rules.

These rules are real engine primitives, but they are intentionally
**not** part of the default :data:`scanner.rules.registry.RULES` set,
so the default scan output for existing callers is unchanged.

A caller that needs them - the PurpleGuard security workforce - passes
them explicitly:

    from scanner.engine import SecurityScanner
    from scanner.rules.optional import OPTIONAL_RULES

    scanner = SecurityScanner(target, rules=OPTIONAL_RULES)
"""

from scanner.rules.secrets_in_comments import CommentSecretRule
from scanner.rules.silent_failure import SilentFailureRule

OPTIONAL_RULES = [
    SilentFailureRule(),
    CommentSecretRule(),
]

__all__ = ["OPTIONAL_RULES", "SilentFailureRule", "CommentSecretRule"]
