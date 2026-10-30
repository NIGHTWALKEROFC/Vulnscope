import http.server
import socketserver
import threading
import time

import pytest

from vulnscope.config import Config


@pytest.fixture
def home(tmp_path):
    return tmp_path / "home"


@pytest.fixture
def cfg(home):
    return Config.load(home)


class _Handler(http.server.BaseHTTPRequestHandler):
    PAGE = (
        b"<html><head><title>Fixture</title></head><body>"
        b"<form method=\"post\" action=\"/login\"><input type=password name=p></form>"
        b"<script src=\"https://cdn.example.invalid/jquery-1.12.4.min.js\"></script>"
        b"<!-- TODO remove password=hunter2 before launch -->"
        b"</body></html>"
    )

    def do_GET(self):
        if self.path == "/vulnscope-missing":
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.send_header("Content-Type", "text/html")
        self.send_header("Set-Cookie", "sessionid=abc123; Path=/")
        self.end_headers()
        self.wfile.write(self.PAGE)

    def log_message(self, *a):
        pass


@pytest.fixture(scope="session")
def test_server():
    server = socketserver.ThreadingTCPServer(("127.0.0.1", 0), _Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    time.sleep(0.1)
    yield "http://127.0.0.1:%d" % port
    server.shutdown()
