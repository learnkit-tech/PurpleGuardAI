import os
import socket
import subprocess
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path


class LocalTarget:
    """
    Manages a controlled local target owned by PurpleGuard.

    Important safety property:
    PurpleGuard chooses a free local port and passes it to the
    controlled launcher. It never silently connects to an existing
    process on a fixed port.
    """

    def __init__(
        self,
        project_path,
        host="127.0.0.1",
        port=None,
    ):
        self.project_path = Path(
            project_path
        ).resolve()

        self.host = host
        self.port = port
        self.process = None

    def _find_free_port(self):
        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:
            sock.bind((self.host, 0))
            return sock.getsockname()[1]

    def _port_available(self):
        if self.port is None:
            return True

        with socket.socket(
            socket.AF_INET,
            socket.SOCK_STREAM
        ) as sock:
            sock.settimeout(0.5)

            try:
                sock.connect((self.host, self.port))
                return False
            except (ConnectionRefusedError, OSError):
                return True

    def start(self):

        if self.process is not None:
            raise RuntimeError(
                "LocalTarget is already running."
            )

        server_file = self.project_path / "run_server.py"

        if not server_file.exists():
            raise FileNotFoundError(
                "Controlled target launcher not found: "
                f"{server_file}"
            )

        # If no port was supplied, allocate a free one.
        if self.port is None:
            self.port = self._find_free_port()

        # Never attach to an unrelated existing service.
        if not self._port_available():
            raise RuntimeError(
                "Refusing to start controlled target because "
                f"{self.host}:{self.port} is already in use."
            )

        environment = os.environ.copy()
        environment["PURPLEGUARD_HOST"] = self.host
        environment["PURPLEGUARD_PORT"] = str(self.port)

        self.process = subprocess.Popen(
            [
                sys.executable,
                str(server_file),
            ],
            cwd=str(self.project_path),
            env=environment,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.PIPE,
        )

        deadline = time.time() + 10

        while time.time() < deadline:

            # The process died before becoming reachable.
            if self.process.poll() is not None:

                stderr = self.process.stderr.read()

                raise RuntimeError(
                    "Controlled target failed to start.\n"
                    f"STDERR:\n"
                    f"{stderr.decode(errors='ignore')}"
                )

            try:

                # Any HTTP response proves the server is up.
                # Do not assume the target exposes any specific
                # route for healthchecking.
                with urllib.request.urlopen(
                    self.base_url,
                    timeout=1,
                ) as response:
                    return {
                        "status": "STARTED",
                        "host": self.host,
                        "port": self.port,
                        "pid": self.process.pid,
                        "base_url": self.base_url,
                    }

            except urllib.error.HTTPError:

                # An HTTP error status still proves the HTTP
                # server is running and answering requests.
                return {
                    "status": "STARTED",
                    "host": self.host,
                    "port": self.port,
                    "pid": self.process.pid,
                    "base_url": self.base_url,
                }

            except (
                urllib.error.URLError,
                ConnectionRefusedError,
                TimeoutError,
            ):
                time.sleep(0.25)

        self.stop()

        raise RuntimeError(
            "Controlled target process started, but the "
            "HTTP target did not become reachable."
        )

    def stop(self):

        if self.process is None:
            return {
                "status": "NOT_RUNNING"
            }

        if self.process.poll() is None:

            self.process.terminate()

            try:
                self.process.wait(timeout=3)

            except subprocess.TimeoutExpired:

                self.process.kill()
                self.process.wait()

        result = {
            "status": "STOPPED",
            "pid": self.process.pid,
        }

        self.process = None

        return result

    @property
    def base_url(self):
        if self.port is None:
            raise RuntimeError(
                "Target has not been started yet."
            )

        return (
            f"http://{self.host}:{self.port}"
        )
