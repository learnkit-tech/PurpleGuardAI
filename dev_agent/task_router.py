def route_task(task):

    task = task.lower()

    if "dashboard" in task:
        return {
            "area": "dashboard",
            "files": [
                "dashboard/app.py",
                "dashboard/templates/index.html"
            ],
            "goal": "Create a web interface for monitoring PurpleGuardAI."
        }


    if "api" in task:
        return {
            "area": "api",
            "files": [
                "api/server.py"
            ],
            "goal": "Create API endpoints for scanner operations."
        }


    if "vulnerability" in task or "rules" in task:
        return {
            "area": "scanner",
            "files": [
                "scanner/rules/"
            ],
            "goal": "Improve vulnerability detection."
        }


    if "sarif" in task:
        return {
            "area": "reporting",
            "files": [
                "scanner/reporting/sarif.py"
            ],
            "goal": "Generate SARIF security reports."
        }


    if "security" in task or "secure" in task:
        return {
            "area": "security",
            "files": [
                "scanner/",
                "hacker/",
                "purpleguard_runner.py"
            ],
            "goal": (
                "Run the PurpleGuard security pipeline "
                "through the ECC bridge."
            )
        }


    return {
        "area": "general",
        "files": [],
        "goal": task
    }

