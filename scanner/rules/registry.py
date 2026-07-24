from scanner.rules.password import check_password
from scanner.rules.dangerous import check_dangerous_functions
from scanner.rules.secrets import check_secrets


RULES = [
    {
        "id": "PG001",
        "name": "Hardcoded Password",
        "function": check_password
    },
    {
        "id": "PG002",
        "name": "Dangerous eval Usage",
        "function": check_dangerous_functions
    },
    {
        "id": "PG003",
        "name": "Hardcoded Secret",
        "function": check_secrets
    }
]
