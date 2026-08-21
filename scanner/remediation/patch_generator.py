class PatchGenerator:
    def generate_patch(self, finding):
        vulnerability = finding.get("type")

        if vulnerability == "Hardcoded Password":
            return {
                "description": "Move password to environment variable",
                "before": 'password = "admin123"',
                "after": (
                    "import os\n"
                    "password = os.getenv('APP_PASSWORD')"
                )
            }

        if vulnerability == "Dangerous eval":
            return {
                "description": "Remove unsafe eval usage",
                "before": "eval(user_input)",
                "after": "Use safe parsing methods instead"
            }

        return {
            "description": "No automatic patch available",
            "before": None,
            "after": None
        }
