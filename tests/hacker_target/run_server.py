import os

from werkzeug.serving import run_simple
from app import app


if __name__ == "__main__":

    host = os.environ.get(
        "PURPLEGUARD_HOST",
        "127.0.0.1"
    )

    port = int(
        os.environ.get(
            "PURPLEGUARD_PORT",
            "8765"
        )
    )

    run_simple(
        host,
        port,
        app,
        use_reloader=False,
        use_debugger=False,
    )
