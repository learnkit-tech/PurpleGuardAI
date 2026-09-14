from app import app


def test_sql_injection_is_blocked():
    client = app.test_client()

    response = client.get(
        "/search",
        query_string={
            "username": "' OR '1'='1"
        },
    )

    assert response.status_code == 200

    data = response.get_json()

    assert data["results"] == []


def test_dynamic_code_execution_is_blocked():
    client = app.test_client()

    response = client.get(
        "/calculate",
        query_string={
            "expression": "2+3"
        },
    )

    # The vulnerable version returns HTTP 200 with result=5.
    # The patched version must not evaluate the expression.
    assert not (
        response.status_code == 200
        and response.get_json().get("result") == 5
    )
