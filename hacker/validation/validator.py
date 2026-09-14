import json
import urllib.error
import urllib.parse
import urllib.request


class LocalAttackValidator:

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def request(self, path, params=None):

        url = self.base_url + path

        if params:
            url += "?" + urllib.parse.urlencode(params)

        try:

            with urllib.request.urlopen(
                url,
                timeout=5,
            ) as response:

                body = response.read().decode(
                    errors="replace"
                )

                return {
                    "status": response.status,
                    "body": body,
                    "error": None,
                    "url": url,
                }

        except urllib.error.HTTPError as exc:

            body = exc.read().decode(
                errors="replace"
            )

            return {
                "status": exc.code,
                "body": body,
                "error": str(exc),
                "url": url,
            }

        except Exception as exc:

            return {
                "status": None,
                "body": "",
                "error": str(exc),
                "url": url,
            }

    def validate_calculator(self):

        """
        Controlled validation of the deliberately vulnerable
        local calculator endpoint.

        We use a harmless arithmetic expression. The purpose is
        to establish whether the server evaluates attacker-
        supplied input, not to execute an operating-system command.
        """

        payload = "2+3"

        result = self.request(
            "/calculate",
            {
                "expression": payload
            },
        )

        body = result.get("body", "")

        evaluated = (
            '"result": 5' in body
            or '"result":5' in body
        )

        return {
            "attack": "DYNAMIC_CODE_EXECUTION",
            "payload": payload,
            "request": result,
            "validated": evaluated,
            "evidence": (
                "Server evaluated attacker-controlled "
                "expression."
                if evaluated
                else
                "Server did not demonstrate evaluation "
                "of the supplied expression."
            ),
        }

    def validate_sql_behavior(self):

        """
        Controlled SQL-injection validation against the local
        deliberately vulnerable application.

        The payload is designed only to test whether the query
        behavior changes. It does not attempt destructive SQL.
        """

        baseline = self.request(
            "/search",
            {
                "username": "nobody-that-does-not-exist"
            },
        )

        test_payload = "' OR '1'='1"

        attack = self.request(
            "/search",
            {
                "username": test_payload
            },
        )

        baseline_body = baseline.get(
            "body",
            ""
        )

        attack_body = attack.get(
            "body",
            ""
        )

        behavior_changed = (
            attack_body != baseline_body
            and attack.get("status") == 200
        )

        return {
            "attack": "SQL_INJECTION",
            "payload": test_payload,
            "baseline": baseline,
            "attack_request": attack,
            "validated": behavior_changed,
            "evidence": (
                "Application behavior changed after "
                "controlled SQL injection input."
                if behavior_changed
                else
                "Controlled input did not demonstrate "
                "a confirmed SQL injection."
            ),
        }

    def validate_path_traversal(self):

        """
        Controlled path-traversal validation against the local
        deliberately vulnerable /read endpoint.

        Requests a file outside the endpoint's intended
        directory and checks for a unique marker string that
        only exists in that file. Proves the escape actually
        works rather than just assuming it from the code shape.
        """

        marker = "PURPLEGUARD_SECRET_MARKER"

        result = self.request(
            "/read",
            {
                "file": "../secret.txt"
            },
        )

        body = result.get("body", "")

        validated = marker in body

        return {
            "attack": "PATH_TRAVERSAL",
            "payload": "../secret.txt",
            "request": result,
            "validated": validated,
            "evidence": (
                "Server returned contents of a file "
                "outside the intended directory."
                if validated
                else
                "Controlled input did not demonstrate "
                "a confirmed path traversal."
            ),
        }

    def validate_all(self):

        return {
            "calculator": self.validate_calculator(),
            "sql": self.validate_sql_behavior(),
            "path_traversal": self.validate_path_traversal(),
        }
