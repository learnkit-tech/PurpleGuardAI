from scanner.rules.password import HardcodedPasswordRule
from scanner.rules.dangerous import DangerousEvalRule
from scanner.rules.secrets import HardcodedSecretRule
from scanner.rules.sql_injection import SQLInjectionRule
from scanner.rules.command_injection import CommandInjectionRule
from scanner.rules.path_traversal import PathTraversalRule
from scanner.rules.xss import XSSRule
from scanner.rules.open_redirect import OpenRedirectRule
from scanner.rules.ssrf import SSRFRule


RULES = [
    HardcodedPasswordRule(),
    DangerousEvalRule(),
    HardcodedSecretRule(),
    SQLInjectionRule(),
    CommandInjectionRule(),
    PathTraversalRule(),
    XSSRule(),
    OpenRedirectRule(),
    SSRFRule()
]
