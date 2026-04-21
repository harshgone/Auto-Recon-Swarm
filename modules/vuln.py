"""
vuln.py — Searchsploit wrapper for Auto-Recon Swarm.

Queries the local ExploitDB (via searchsploit) for each detected service version
and collects matching exploit IDs, titles, and file paths.
"""

import subprocess
import shutil
import logging
import json
import re
from pathlib import Path
from typing import Optional

logger = logging.getLogger("recon.vuln")


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


def _build_search_term(port_info: dict) -> Optional[str]:
    """
    Build a searchsploit query string from a port dict.

    Strategy:
      1. Use product + version if both available.
      2. Fall back to product alone.
      3. Fall back to service name.
    Returns None if nothing useful to search.
    """
    product = port_info.get("product", "").strip()
    version = port_info.get("version", "").strip()
    service = port_info.get("service", "").strip()

    # Strip trailing qualifiers like "(Ubuntu)" for cleaner matches
    product = re.sub(r"\s*\([^)]+\)", "", product).strip()

    # Extract only the first version number (e.g. "2.3.4" from "2.3.4 beta")
    ver_match = re.match(r"[\d.]+", version)
    clean_version = ver_match.group(0) if ver_match else ""

    if product and clean_version:
        return f"{product} {clean_version}"
    if product:
        return product
    if service and service not in ("unknown", "tcpwrapped"):
        return service
    return None


def run_searchsploit(open_ports: list, output_dir: Path,
                     verbose: bool = False, demo: bool = False) -> dict:
    """
    Run searchsploit for each open port's service/version.

    Args:
        open_ports:  List of parsed port dicts from scanner.
        output_dir:  Directory for raw output.
        verbose:     Log each query result.
        demo:        Return synthetic results without running searchsploit.

    Returns:
        dict: {results: [{port, service, query, exploits: [{id, title, path, type}]}],
               total_exploits, error}
    """
    result = {"results": [], "total_exploits": 0, "error": None}

    if demo:
        logger.info("[DEMO] Returning synthetic searchsploit data.")
        result["results"] = [
            {
                "port": 21,
                "service": "ftp / vsftpd 2.3.4",
                "query": "vsftpd 2.3.4",
                "exploits": [
                    {
                        "id": "17491",
                        "title": "vsftpd 2.3.4 - Backdoor Command Execution (Metasploit)",
                        "path": "/usr/share/exploitdb/exploits/unix/remote/17491.rb",
                        "type": "remote",
                    }
                ],
            },
            {
                "port": 22,
                "service": "ssh / OpenSSH 4.7p1",
                "query": "OpenSSH 4.7",
                "exploits": [
                    {
                        "id": "45233",
                        "title": "OpenSSH < 6.6 SFTP (x64) - Command Execution",
                        "path": "/usr/share/exploitdb/exploits/linux/remote/45233.py",
                        "type": "remote",
                    },
                    {
                        "id": "1902",
                        "title": "OpenSSH 2.x/3.x/4.x - Username Enumeration",
                        "path": "/usr/share/exploitdb/exploits/linux/remote/1902.pl",
                        "type": "remote",
                    },
                ],
            },
            {
                "port": 445,
                "service": "netbios-ssn / Samba 3.0.20",
                "query": "Samba 3.0.20",
                "exploits": [
                    {
                        "id": "16320",
                        "title": "Samba 3.0.20 < 3.0.25rc3 - 'Username' map script' Command Execution (Metasploit)",
                        "path": "/usr/share/exploitdb/exploits/unix/remote/16320.rb",
                        "type": "remote",
                    }
                ],
            },
        ]
        result["total_exploits"] = sum(
            len(r["exploits"]) for r in result["results"]
        )
        return result

    if not _tool_available("searchsploit"):
        logger.warning("searchsploit not found — skipping vuln search.")
        result["error"] = "searchsploit not installed."
        return result

    # Avoid duplicate queries
    seen_queries: set = set()
    port_results = []

    for port_info in open_ports:
        query = _build_search_term(port_info)
        if not query or query.lower() in seen_queries:
            continue
        seen_queries.add(query.lower())

        port_label = (
            f"{port_info.get('service', 'unknown')} / "
            f"{port_info.get('product', '')} "
            f"{port_info.get('version', '')}".strip()
        )

        logger.info("searchsploit: querying '%s' (port %s)", query,
                    port_info.get("port", "?"))

        exploits = _run_single_query(query, output_dir, verbose)

        port_results.append({
            "port":     port_info.get("port"),
            "service":  port_label,
            "query":    query,
            "exploits": exploits,
        })

    result["results"]        = port_results
    result["total_exploits"] = sum(len(r["exploits"]) for r in port_results)
    logger.info("searchsploit found %d total exploits.", result["total_exploits"])
    return result


def _run_single_query(query: str, output_dir: Path, verbose: bool) -> list:
    """
    Execute a single searchsploit query and parse JSON output.

    Returns:
        List of exploit dicts: {id, title, path, type}
    """
    cmd = ["searchsploit", "--json", "--disable-colour", query]

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=30
        )
        raw_text = proc.stdout.strip()

        # Save raw output
        safe_name = re.sub(r"[^\w\s-]", "", query).strip().replace(" ", "_")
        raw_file = output_dir / f"searchsploit_{safe_name}.json"
        raw_file.write_text(raw_text, encoding="utf-8")

        if verbose:
            logger.debug("[searchsploit] %s", raw_text[:1000])

        return _parse_searchsploit_json(raw_text)

    except subprocess.TimeoutExpired:
        logger.warning("searchsploit timed out for query: %s", query)
        return []
    except Exception as exc:
        logger.error("searchsploit error: %s", exc)
        return []


def _parse_searchsploit_json(raw: str) -> list:
    """
    Parse searchsploit --json output.

    Expected structure:
        {"RESULTS_EXPLOIT": [{EDB-ID, Title, Path, Type, ...}], ...}
    """
    exploits = []
    if not raw:
        return exploits

    try:
        data = json.loads(raw)
    except json.JSONDecodeError:
        # Fallback: sometimes searchsploit prefixes output with color codes
        cleaned = re.sub(r"\x1b\[[0-9;]*m", "", raw)
        try:
            data = json.loads(cleaned)
        except json.JSONDecodeError:
            logger.warning("Could not parse searchsploit JSON output.")
            return exploits

    for entry in data.get("RESULTS_EXPLOIT", []):
        exploits.append({
            "id":    entry.get("EDB-ID", ""),
            "title": entry.get("Title", ""),
            "path":  entry.get("Path", ""),
            "type":  entry.get("Type", ""),
        })

    return exploits
