import pickle
import urllib.error
import urllib.parse
import urllib.request


class LocalAttackValidator:

    def __init__(self, base_url):
        self.base_url = base_url.rstrip("/")

    def request(self, path, params=None, data=None):

        url = self.base_url + path

        if params:
            url += "?" + urllib.parse.urlencode(params)

        try:

            # Redirects are never followed: an open-redirect check
            # must read the server's own Location header instead.
            class _NoRedirect(
                urllib.request.HTTPRedirectHandler
            ):

                def redirect_request(
                    self,
                    req,
                    fp,
                    code,
                    msg,
                    headers,
                    newurl,
                ):
                    return None

            no_redirect_opener = urllib.request.build_opener(
                _NoRedirect
            )

            target = url

            if data is not None:

                # Supplying raw bytes turns the request into a
                # POST body, which is how serialized payloads are
                # delivered to deserialization sinks.
                target = urllib.request.Request(
                    url,
                    data=data,
                )

            with no_redirect_opener.open(
                target,
                timeout=5,
            ) as response:

                body = response.read().decode(
                    errors="replace"
                )

                return {
                    "status": response.status,
                    "body": body,
                    "headers": dict(response.headers),
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
                "headers": dict(exc.headers or {}),
                "error": str(exc),
                "url": url,
            }

        except Exception as exc:

            return {
                "status": None,
                "body": "",
                "headers": {},
                "error": str(exc),
                "url": url,
            }

    def validate_deserialization(self):

        """
        Controlled insecure-deserialization validation against the
        local /load endpoint.

        Sends a pickle payload containing ONLY a plain dictionary
        with a unique marker. The endpoint's echo of the deserialized
        object proves the server reconstructs objects from
        attacker-supplied serialized bytes. Deliberately data-only:
        a __reduce__ payload would prove code execution, but the
        project never executes destructive proof payloads when a
        harmless behavioral marker is sufficient.
        """

        marker = "PURPLEGUARD-PG10-MARKER"

        payload = pickle.dumps(
            {"pg": marker}
        )

        result = self.request(
            "/load",
            data=payload,
        )

        body = result.get("body", "")

        deserialized = marker in body

        return {
            "attack": "DESERIALIZATION",
            "payload": (
                "pickle.dumps({'pg': '" + marker + "'})"
            ),
            "request": result,
            "validated": deserialized,
            "evidence": (
                "Server deserialized attacker-controlled "
                "serialized data and reconstructed the "
                "attacker-supplied object."
                if deserialized
                else
                "Server did not deserialize the "
                "attacker-controlled payload."
            ),
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

    def validate_command_execution(self):

        """
        Controlled validation of a command-injection sink.

        The payload only injects an extra harmless echo that writes
        to standard output. It proves that attacker-controlled text
        was interpreted by a shell - and it never touches the
        filesystem or runs any destructive command.
        """

        marker = "PURPLEGUARD_CMD_MARKER"

        # Leading with the harmless "true" builtin keeps the payload
        # syntactically valid whether the sink uses the input as the
        # whole command line or appends it to a fixed command.
        payload = f"true; echo {marker}"

        result = self.request(
            "/run",
            {
                "command": payload
            },
        )

        body = result.get("body", "")

        # The vulnerable endpoint executes the command and returns
        # its combined output. The shell-injected echo makes the
        # marker appear in that output.
        validated = marker in body

        return {
            "attack": "COMMAND_INJECTION",
            "payload": payload,
            "request": result,
            "validated": validated,
            "evidence": (
                "Server executed attacker-controlled shell input."
                if validated
                else
                "Controlled input did not demonstrate "
                "command execution."
            ),
        }

    def validate_xss_reflection(self):

        """
        Controlled reflected-XSS validation.

        The payload is a unique, harmless marker string. The check
        is purely behavioral: the marker is reflected verbatim into
        the response body (no HTML entity encoding applied).
        No scripting is involved.
        """

        # The marker includes HTML-special characters on purpose:
        # an escaping fix turns them into HTML entities, so a raw
        # reflection proves output encoding is missing while an
        # encoded reflection proves the fix works.
        marker = "<pgxss-7f3a9b2c4e>"

        result = self.request(
            "/greet",
            {
                "name": marker
            },
        )

        body = result.get("body", "")

        reflected_raw = marker in body
        reflected_encoded = (
            "&lt;" in body
            or "&amp;" in body
            or "&#x" in body
        )

        validated = (
            reflected_raw
            and not reflected_encoded
        )

        return {
            "attack": "XSS",
            "payload": marker,
            "request": result,
            "validated": validated,
            "evidence": (
                "Marker reflected into the response body "
                "without HTML encoding."
                if validated
                else
                "Reflection was escaped or absent; no "
                "confirmed XSS reflection."
            ),
        }

    def validate_open_redirect(self):

        """
        Controlled open-redirect validation.

        Sends a redirect target on a non-routable TEST-NET host and
        never follows the redirect. Confirmation is based purely on
        the Location header the server itself returns.
        """

        import re

        payload = "http://192.0.2.77/next"

        result = self.request(
            "/go",
            {
                "next": payload
            },
        )

        status = result.get("status")

        location = result.get("headers", {}).get(
            "Location",
            "",
        )

        redirected_out = (
            location == payload
            or bool(
                location
                and re.match(
                    r"^https?://192\.0\.2\.77",
                    location,
                )
            )
        )

        return {
            "attack": "OPEN_REDIRECT",
            "payload": payload,
            "request": result,
            "validated": redirected_out,
            "evidence": (
                "Server returned a redirect to an "
                "attacker-chosen absolute URL."
                if redirected_out
                else
                "Server did not redirect to the "
                "attacker-controlled destination."
            ),
        }

    def validate_ssrf(self):

        """
        Controlled SSRF validation against the local /fetch
        endpoint.

        Asks the server to fetch a TEST-NET address that cannot
        exist in the sandbox. Confirmation is a response body
        marker emitted by the vulnerable endpoint's own error
        handler, proving the server attempted the attacker-chosen
        destination. No external network access is performed.
        """

        import re

        payload = "http://192.0.2.99/metadata"

        result = self.request(
            "/fetch",
            {
                "url": payload
            },
        )

        body = result.get("body", "")

        # The vulnerable endpoint surfaces the failed outbound
        # request's error text; the TEST-NET host name in the
        # response proves the server tried the attacker URL.
        fetched_attacker_url = bool(
            re.search(
                r"192\.0\.2\.99",
                body,
            )
        )

        return {
            "attack": "SSRF",
            "payload": payload,
            "request": result,
            "validated": fetched_attacker_url,
            "evidence": (
                "Server attempted a request to the "
                "attacker-controlled destination."
                if fetched_attacker_url
                else
                "Server did not attempt the "
                "attacker-controlled destination."
            ),
        }
