from scanner.rules.password import HardcodedPasswordRule
from scanner.rules.dangerous import DangerousEvalRule
from scanner.rules.secrets import HardcodedSecretRule
from scanner.rules.sql_injection import SQLInjectionRule


RULES = [
    HardcodedPasswordRule(),
    DangerousEvalRule(),
    HardcodedSecretRule(),
    SQLInjectionRule()
]
