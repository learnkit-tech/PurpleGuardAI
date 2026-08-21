def get_fix(vulnerability_id):

    fixes = {

        "PG001": {
            "title": "Move credentials to environment variables",
            "before": 'password = "admin123"',
            "after": 'import os\npassword = os.getenv("APP_PASSWORD")'
        },

        "PG002": {
            "title": "Replace unsafe eval usage",
            "before": "result = eval(user_input)",
            "after": "result = ast.literal_eval(user_input)"
        },

        "PG003": {
            "title": "Remove hardcoded secrets",
            "before": 'API_KEY = "secret_value"',
            "after": 'import os\nAPI_KEY = os.getenv("API_KEY")'
        },

        "PG004": {
            "title": "Use parameterized SQL queries",
            "before": 'query = "SELECT * FROM users WHERE id=" + user_id',
            "after": 'cursor.execute("SELECT * FROM users WHERE id=?", (user_id,))'
        }
    }

    return fixes.get(
        vulnerability_id,
        {
            "title": "No automated fix available",
            "before": "",
            "after": ""
        }
    )
