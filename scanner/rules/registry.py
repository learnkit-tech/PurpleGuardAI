from scanner.rules.password import check_password
from scanner.rules.dangerous import check_dangerous_functions


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
    }
]
