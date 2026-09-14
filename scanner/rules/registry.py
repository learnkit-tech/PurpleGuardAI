from scanner.rules.password import HardcodedPasswordRule
from scanner.rules.dangerous import DangerousEvalRule
from scanner.rules.secrets import HardcodedSecretRule
from scanner.rules.sql_injection import SQLInjectionRule
from scanner.rules.command_injection import CommandInjectionRule
from scanner.rules.path_traversal import PathTraversalRule


RULES = [
    HardcodedPasswordRule(),
    DangerousEvalRule(),
    HardcodedSecretRule(),
    SQLInjectionRule(),
    CommandInjectionRule(),
    PathTraversalRule()
]
