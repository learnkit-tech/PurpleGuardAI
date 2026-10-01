import io
import re
import tokenize

from scanner.rules.base import Rule


class CommentSecretRule(Rule):
    """PG012: credentials leaked in source comments.

    The AST-based secret rule (PG003) only sees assignments. Secrets
    are frequently pasted into comments and docstrings during
    debugging and then forgotten, so this rule tokenizes the file and
    inspects comment text for credential-shaped assignments:

        # api_key = sk_live_...
        # password: hunter2

    Deliberately conservative: the value after the separator must be
    non-trivial (at least 8 characters) and contain no whitespace, so
    prose like "# password reset is handled elsewhere" is not flagged.
    """

    id = "PG012"
    name = "Secret in Comment"
    severity = "MEDIUM"
    category = "Secrets Management"

    KEYWORDS = (
        "password",
        "passwd",
        "secret",
        "api_key",
        "apikey",
        "api-key",
        "token",
        "access_key",
        "private_key",
        "client_secret",
    )

    PATTERN = re.compile(
        r"(?P<key>[A-Za-z0-9_\-]+)\s*(?P<sep>[=:])\s*"
        r"(?P<value>[^\s'\"]{8,})",
    )

    def check(self, filepath, lines):
        findings = []

        source = "".join(lines)

        try:
            tokens = list(tokenize.generate_tokens(io.StringIO(source).readline))
        except (tokenize.TokenError, IndentationError, SyntaxError):
            return findings

        for token in tokens:

            if token.type != tokenize.COMMENT:
                continue

            comment = token.string
            line_number = token.start[0]

            for match in self.PATTERN.finditer(comment):

                key = match.group("key").lower()

                if not any(keyword in key for keyword in self.KEYWORDS):
                    continue

                findings.append({
                    "id": self.id,
                    "file": filepath,
                    "line": line_number,
                    "code": comment.strip(),
                })

                break

        return findings
