"""
smb.py — SMB enumeration wrappers for Auto-Recon Swarm.

Runs smbclient (share listing) and enum4linux (full SMB/RPC enumeration).
Only invoked when ports 139 or 445 are detected open.
"""

import subprocess
import shutil
import logging
import re
from pathlib import Path

logger = logging.getLogger("recon.smb")

SMB_PORTS = {139, 445}


def _tool_available(name: str) -> bool:
    return shutil.which(name) is not None


# ─────────────────────────── smbclient ───────────────────────────────────────

def run_smbclient(target: str, open_ports: list, output_dir: Path,
                  verbose: bool = False, demo: bool = False) -> dict:
    """
    List SMB shares via smbclient -L.

    Returns:
        dict: {shares: [{name, type, comment}], error}
    """
    result = {"shares": [], "raw": "", "error": None}

    has_smb = any(p["port"] in SMB_PORTS for p in open_ports)
    if not has_smb:
        logger.info("No SMB ports open — skipping smbclient.")
        result["error"] = "No SMB ports detected."
        return result

    if demo:
        logger.info("[DEMO] Returning synthetic smbclient data.")
        result["shares"] = [
            {"name": "print$",  "type": "Disk",      "comment": "Printer Drivers"},
            {"name": "tmp",     "type": "Disk",      "comment": "oh noes!"},
            {"name": "opt",     "type": "Disk",      "comment": ""},
            {"name": "IPC$",    "type": "IPC",       "comment": "IPC Service (metasploitable server)"},
            {"name": "ADMIN$",  "type": "IPC",       "comment": "IPC Service (metasploitable server)"},
        ]
        return result

    if not _tool_available("smbclient"):
        logger.warning("smbclient not found — skipping.")
        result["error"] = "smbclient not installed."
        return result

    cmd = ["smbclient", "-L", f"//{target}", "-N", "--option=client min protocol=NT1"]
    logger.info("Running: %s", " ".join(cmd))

    raw_file = output_dir / "smbclient.txt"
    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=60
        )
        output = proc.stdout + proc.stderr
        raw_file.write_text(output, encoding="utf-8")
        result["raw"] = output
        if verbose:
            logger.debug("[smbclient] %s", output[:2000])
        result["shares"] = _parse_smbclient(output)
    except subprocess.TimeoutExpired:
        logger.warning("smbclient timed out.")
        result["error"] = "Timed out"
    except Exception as exc:
        logger.error("smbclient error: %s", exc)
        result["error"] = str(exc)

    return result


def _parse_smbclient(output: str) -> list:
    """Parse 'smbclient -L' output into a list of share dicts."""
    shares = []
    # Lines like: \tshare_name         Disk       comment here
    pattern = re.compile(
        r"^\s+(\S+)\s+(Disk|IPC|Printer|IPCSERV|PRINTQ)\s*(.*)", re.IGNORECASE
    )
    for line in output.splitlines():
        m = pattern.match(line)
        if m:
            shares.append({
                "name":    m.group(1),
                "type":    m.group(2),
                "comment": m.group(3).strip(),
            })
    return shares


# ─────────────────────────── enum4linux ──────────────────────────────────────

def run_enum4linux(target: str, open_ports: list, output_dir: Path,
                   verbose: bool = False, demo: bool = False) -> dict:
    """
    Run enum4linux for comprehensive SMB/RPC enumeration.

    Returns:
        dict: {users, groups, password_policy, workgroup, raw_output, error}
    """
    result = {
        "users": [],
        "groups": [],
        "password_policy": {},
        "workgroup": "",
        "raw_output": "",
        "error": None,
    }

    has_smb = any(p["port"] in SMB_PORTS for p in open_ports)
    if not has_smb:
        logger.info("No SMB ports open — skipping enum4linux.")
        result["error"] = "No SMB ports detected."
        return result

    if demo:
        logger.info("[DEMO] Returning synthetic enum4linux data.")
        result.update({
            "workgroup": "WORKGROUP",
            "users": [
                {"uid": "0",  "username": "root",    "comment": "root"},
                {"uid": "1",  "username": "daemon",  "comment": "daemon"},
                {"uid": "1000", "username": "msfadmin", "comment": "msfadmin,,,"},
                {"uid": "1001", "username": "user",  "comment": "just a user,111,,"},
            ],
            "groups": ["root", "daemon", "bin", "sys", "adm", "msfadmin"],
            "password_policy": {
                "min_password_length": "5",
                "password_history":    "None",
                "maximum_password_age": "None",
                "account_lockout":     "None",
            },
        })
        return result

    # Prefer enum4linux-ng if available; fall back to enum4linux
    tool = "enum4linux-ng" if _tool_available("enum4linux-ng") else "enum4linux"
    if not _tool_available(tool):
        logger.warning("enum4linux / enum4linux-ng not found — skipping.")
        result["error"] = f"{tool} not installed."
        return result

    raw_file = output_dir / "enum4linux.txt"

    if tool == "enum4linux-ng":
        cmd = ["enum4linux-ng", "-A", target]
    else:
        cmd = ["enum4linux", "-a", target]

    logger.info("Running: %s", " ".join(cmd))

    try:
        proc = subprocess.run(
            cmd, capture_output=True, text=True, timeout=300
        )
        output = proc.stdout + proc.stderr
        raw_file.write_text(output, encoding="utf-8")
        result["raw_output"] = output
        if verbose:
            logger.debug("[enum4linux] %s", output[:3000])

        result["users"]           = _parse_users(output)
        result["groups"]          = _parse_groups(output)
        result["workgroup"]       = _parse_workgroup(output)
        result["password_policy"] = _parse_password_policy(output)

    except subprocess.TimeoutExpired:
        logger.warning("enum4linux timed out.")
        result["error"] = "Timed out"
    except Exception as exc:
        logger.error("enum4linux error: %s", exc)
        result["error"] = str(exc)

    return result


def _parse_users(output: str) -> list:
    """Extract user entries from enum4linux output."""
    users = []
    # Pattern: user:[username] rid:[RID]  or  index: 0x1  RID: 0x1f4  ...  username: Administrator
    for line in output.splitlines():
        # enum4linux classic style: user:[name] rid:[N]
        m = re.search(r"user:\[(\S+)\]\s+rid:\[([^\]]+)\]", line, re.IGNORECASE)
        if m:
            users.append({"username": m.group(1), "uid": m.group(2), "comment": ""})
            continue
        # enum4linux-ng style: Username: alice
        m2 = re.match(r"\s*[Uu]sername:\s+(\S+)", line)
        if m2:
            users.append({"username": m2.group(1), "uid": "", "comment": ""})
    # De-duplicate
    seen = set()
    deduped = []
    for u in users:
        if u["username"] not in seen:
            seen.add(u["username"])
            deduped.append(u)
    return deduped


def _parse_groups(output: str) -> list:
    """Extract group names from enum4linux output."""
    groups = []
    for line in output.splitlines():
        m = re.search(r"group:\[([^\]]+)\]", line, re.IGNORECASE)
        if m:
            name = m.group(1)
            if name not in groups:
                groups.append(name)
    return groups


def _parse_workgroup(output: str) -> str:
    """Extract workgroup/domain name."""
    for line in output.splitlines():
        m = re.search(r"[Ww]orkgroup\s*[:/]\s*(\S+)", line)
        if m:
            return m.group(1)
    return ""


def _parse_password_policy(output: str) -> dict:
    """Extract basic password policy fields."""
    policy = {}
    patterns = {
        "min_password_length":  r"[Mm]inimum [Pp]assword [Ll]ength\s*[:\s]+(\d+)",
        "password_history":     r"[Pp]assword [Hh]istory\s*[:\s]+(\S+)",
        "maximum_password_age": r"[Mm]aximum [Pp]assword [Aa]ge\s*[:\s]+(.+)",
        "account_lockout":      r"[Aa]ccount [Ll]ockout\s*[:\s]+(.+)",
    }
    for key, pat in patterns.items():
        m = re.search(pat, output)
        if m:
            policy[key] = m.group(1).strip()
    return policy
