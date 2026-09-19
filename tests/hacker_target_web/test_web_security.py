from web_app import app


def client():
    return app.test_client()


# -------------------------------------------------------------
# Command injection
# -------------------------------------------------------------

def test_subprocess_shell_injection_is_blocked():
    # Command substitution only executes under a real shell, so
    # the vulnerable version leaks "injected" while the fixed
    # version (argument list, shell=False) cannot.
    response = client().get(
        "/run",
        query_string={"command": "$(echo injected)"},
    )

    assert response.status_code in (200, 500)

    body = response.get_data(as_text=True)

    assert "injected" not in body


def test_os_popen_injection_is_blocked():
    response = client().get(
        "/ping",
        query_string={"host": "localhost; echo marker"},
    )

    assert response.status_code in (200, 500)

    body = response.get_data(as_text=True)

    assert "marker" not in body


# -------------------------------------------------------------
# Reflected XSS
# -------------------------------------------------------------

def test_response_reflection_is_escaped():
    # The angle brackets matter: an escaping fix turns them into
    # HTML entities, so a literal reflection proves the bug.
    marker = "<pgxss-7f3a9b2c4e>"

    response = client().get(
        "/greet",
        query_string={"name": marker},
    )

    assert response.status_code in (200, 500)

    # The vulnerable version reflects the marker verbatim.
    assert marker not in response.get_data(as_text=True)


def test_second_response_reflection_is_escaped():
    marker = "<pgxss-9d4e1f0a7b>"

    response = client().get(
        "/page",
        query_string={"who": marker},
    )

    assert response.status_code in (200, 500)

    assert marker not in response.get_data(as_text=True)


# -------------------------------------------------------------
# Open redirect
# -------------------------------------------------------------

def test_redirect_is_constrained():
    response = client().get(
        "/go",
        query_string={"next": "http://192.0.2.77/next"},
    )

    # The vulnerable version redirects off-site.
    location = response.headers.get("Location", "")

    assert not location.startswith("http://192.0.2.77")


def test_second_redirect_is_constrained():
    response = client().get(
        "/jump",
        query_string={"to": "http://192.0.2.77/jump"},
    )

    location = response.headers.get("Location", "")

    assert not location.startswith("http://192.0.2.77")
