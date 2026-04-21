"""
web.py — WhatWeb and Nikto wrappers for Auto-Recon Swarm.

Only invoked when HTTP/HTTPS ports (80, 443, 8080, 8443) are detected open.
"""

import subprocess
import shutil
import logging
import json
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger("recon.web")

HTTP_PORTS = {80, 443, 8080, 8443, 8180, 8000, 8888}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ─────────────────────────── WhatWeb ─────────────────────────────────────────

def run_whatweb(target: str, open_ports: list, output_dir: Path,
                verbose: bool = False, demo: bool = False) -> dict:
    """
    Run WhatWeb against all detected HTTP ports.

    Args:
        target:      Scan target.
        open_ports:  Parsed nmap port list.
        output_dir:  Directory for raw output.
        verbose:     Stream subprocess output if True.
        demo:        Return synthetic results without running the tool.

    Returns:
        dict: {urls_scanned: [...], findings: [{url, technologies: [...]}], error}
    """
    result = {"urls_scanned": [], "findings": [], "error": None}

    http_ports = [p["port"] for p in open_ports if p["port"] in HTTP_PORTS]
    if not http_ports:
        logger.info("No HTTP ports open — skipping WhatWeb.")
        result["error"] = "No HTTP ports detected."
        return result

    if demo:
        logger.info("[DEMO] Returning synthetic WhatWeb data.")
        result["findings"] = [
            {
                "url": f"http://{target}",
                "technologies": [
                    {"name": "Apache", "version": "2.2.8", "detail": ""},
                    {"name": "PHP", "version": "5.2.4", "detail": ""},
                    {"name": "Ubuntu", "version": "", "detail": ""},
                ],
            }
        ]
        result["urls_scanned"] = [f"http://{target}"]
        return result

    if not _tool_available("whatweb"):
        logger.warning("whatweb not found — skipping.")
        result["error"] = "whatweb not installed."
        return result

    for port in http_ports:
        scheme = "https" if port in (443, 8443) else "http"
        url = f"{scheme}://{target}" if port in (80, 443) else f"{scheme}://{target}:{port}"
        result["urls_scanned"].append(url)

        raw_file = output_dir / f"whatweb_{port}.json"
        cmd = [
            "whatweb",
            "--log-json", str(raw_file),
            "--aggression", "3",
            "--no-errors",
            url,
        ]
        logger.info("Running: %s", " ".join(cmd))

        try:
            proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
            if verbose:
                logger.debug("[whatweb stdout] %s", proc.stdout[:2000])
            findings = _parse_whatweb_json(raw_file, url)
            result["findings"].extend(findings)
        except subprocess.TimeoutExpired:
            logger.warning("WhatWeb timed out for %s", url)
        except Exception as exc:
            logger.error("WhatWeb error on %s: %s", url, exc)

    return result


def _parse_whatweb_json(json_file: Path, url: str) -> list:
    """Parse WhatWeb JSON log into a list of finding dicts."""
    if not json_file.exists():
        return []
    try:
        raw = json_file.read_text(encoding="utf-8")
        # WhatWeb outputs one JSON object per line
        techs = []
        for line in raw.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
                # Each plugin is a key in the top-level dict
                for plugin, values in obj.get("plugins", {}).items():
                    version = ""
                    detail = ""
                    if isinstance(values, dict):
                        v_list = values.get("version", [])
                        version = v_list[0] if v_list else ""
                        s_list = values.get("string", [])
                        detail = s_list[0] if s_list else ""
                    techs.append({"name": plugin, "version": version, "detail": detail})
            except json.JSONDecodeError:
                pass
        return [{"url": url, "technologies": techs}]
    except Exception as exc:
        logger.error("WhatWeb parse error: %s", exc)
        return []


# ─────────────────────────── Nikto ───────────────────────────────────────────

def run_nikto(target: str, open_ports: list, output_dir: Path,
              verbose: bool = False, demo: bool = False) -> dict:
    """
    Run Nikto against all detected HTTP ports.

    Args:
        target:      Scan target.
        open_ports:  Parsed nmap port list.
        output_dir:  Directory for raw output.
        verbose:     Stream subprocess output if True.
        demo:        Return synthetic results without running the tool.

    Returns:
        dict: {scanned: [...], findings: [{port, vulnerabilities: [...]}], error}
    """
    result = {"scanned": [], "findings": [], "error": None}

    http_ports = [p["port"] for p in open_ports if p["port"] in HTTP_PORTS]
    if not http_ports:
        logger.info("No HTTP ports open — skipping Nikto.")
        result["error"] = "No HTTP ports detected."
        return result

    if demo:
        logger.info("[DEMO] Returning synthetic Nikto data.")
        result["findings"] = [
            {
                "port": 80,
                "vulnerabilities": [
                    "+ Apache/2.2.8 appears to be outdated (current is at least Apache/2.4.54).",
                    "+ /phpMyAdmin/: phpMyAdmin directory found.",
                    "+ OSVDB-637: /~root/: Allowed to browse root's home directory.",
                    "+ /tikiwiki/: TikiWiki found.",
                    "+ /mutillidae/: Mutillidae found.",
                    "+ /dvwa/: DVWA (Damn Vulnerable Web App) found.",
                ],
            }
        ]
        result["scanned"] = [80]
        return result

    if not _tool_available("nikto"):
        logger.warning("nikto not found — skipping.")
        result["error"] = "nikto not installed."
        return result

    for port in http_ports:
        result["scanned"].append(port)
        raw_file = output_dir / f"nikto_{port}.txt"
        ssl_flag = ["-ssl"] if port in (443, 8443) else []

        cmd = [
            "nikto",
            "-h", target,
            "-p", str(port),
            "-o", str(raw_file),
            "-Format", "txt",
            "-nointeractive",
        ] + ssl_flag

        logger.info("Running: %s", " ".join(cmd))

        try:
            proc = subprocess.run(
                cmd, capture_output=True, text=True, timeout=600
            )
            if verbose:
                logger.debug("[nikto stdout] %s", proc.stdout[:3000])
            vulns = _parse_nikto_output(raw_file, proc.stdout)
            result["findings"].append({"port": port, "vulnerabilities": vulns})
        except subprocess.TimeoutExpired:
            logger.warning("Nikto timed out on port %d", port)
            result["findings"].append({"port": port, "vulnerabilities": [],
                                       "error": "Timed out"})
        except Exception as exc:
            logger.error("Nikto error on port %d: %s", port, exc)

    return result


def _parse_nikto_output(raw_file: Path, stdout: str) -> list:
    """Extract Nikto finding lines from file or stdout fallback."""
    text = ""
    if raw_file.exists():
        text = raw_file.read_text(encoding="utf-8", errors="replace")
    if not text:
        text = stdout

    vulns = []
    for line in text.splitlines():
        line = line.strip()
        # Nikto findings start with '+ '
        if line.startswith("+ ") and len(line) > 5:
            vulns.append(line)
    return vulns
