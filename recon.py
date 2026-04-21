#!/usr/bin/env python3
"""
recon.py — Auto-Recon Swarm
============================
Automated initial reconnaissance for authorized penetration testing.

Usage:
  python recon.py --target 192.168.1.10 --profile quick
  python recon.py --target 192.168.1.10 --profile full --parallel 4 --output my_scan
  python recon.py --demo
  python recon.py --resume output/last_scan/

Author:  Auto-Recon Swarm
License: MIT (for authorized testing only)
"""

import argparse
import json
import logging
import os
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

# ── Optional tqdm (graceful fallback) ────────────────────────────────────────
try:
    from tqdm import tqdm
    HAS_TQDM = True
except ImportError:
    HAS_TQDM = False

# ── Color codes (ANSI) ────────────────────────────────────────────────────────
RESET  = "\033[0m"
BOLD   = "\033[1m"
RED    = "\033[91m"
GREEN  = "\033[92m"
YELLOW = "\033[93m"
BLUE   = "\033[94m"
CYAN   = "\033[96m"
GRAY   = "\033[90m"

# ── Local modules ─────────────────────────────────────────────────────────────
sys.path.insert(0, str(Path(__file__).parent))
from modules.scanner import run_nmap
from modules.web     import run_whatweb, run_nikto
from modules.smb     import run_smbclient, run_enum4linux
from modules.vuln    import run_searchsploit
from modules.report  import generate_html, generate_json, generate_csv


# ─────────────────────────── Logging setup ───────────────────────────────────

def setup_logging(verbose: bool, debug: bool, log_file: Path) -> None:
    """Configure root logger with colored console output and file handler."""
    level = logging.DEBUG if debug else (logging.INFO if verbose else logging.WARNING)

    fmt_file    = "%(asctime)s [%(levelname)-8s] %(name)s — %(message)s"
    fmt_console = "%(message)s"

    root = logging.getLogger()
    root.setLevel(logging.DEBUG)  # capture everything at root

    # File handler — always DEBUG
    fh = logging.FileHandler(log_file, encoding="utf-8")
    fh.setLevel(logging.DEBUG)
    fh.setFormatter(logging.Formatter(fmt_file))
    root.addHandler(fh)

    # Console handler
    ch = logging.StreamHandler(sys.stdout)
    ch.setLevel(level)
    ch.setFormatter(logging.Formatter(fmt_console))
    root.addHandler(ch)


logger = logging.getLogger("recon")


# ─────────────────────────── CLI ─────────────────────────────────────────────

def build_parser() -> argparse.ArgumentParser:
    p = argparse.ArgumentParser(
        prog="recon.py",
        description=(
            "Auto-Recon Swarm — automated initial reconnaissance tool.\n"
            "For authorized penetration testing only."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python recon.py --target 192.168.1.10 --profile quick
  python recon.py --target 192.168.1.10 --profile full --parallel 6 --output pentest_acme
  python recon.py --demo
  python recon.py --resume output/20240101_120000/
        """,
    )

    # Target / scan options
    tgt = p.add_argument_group("Target")
    tgt.add_argument("--target", "-t", metavar="IP/DOMAIN",
                     help="Target IP address or domain name.")
    tgt.add_argument("--profile", choices=["quick", "full"], default="quick",
                     help="Scan profile: 'quick' (top 100 ports) or 'full' (1–65535). Default: quick.")

    # Execution options
    exe = p.add_argument_group("Execution")
    exe.add_argument("--parallel", type=int, default=4, metavar="N",
                     help="Thread pool size for parallel scans. Default: 4.")
    exe.add_argument("--output", "-o", metavar="NAME",
                     help="Output directory name (under output/). Auto-generated if omitted.")

    # Modes
    mode = p.add_argument_group("Special modes")
    mode.add_argument("--demo", action="store_true",
                      help="Run with embedded demo data (no live target needed).")
    mode.add_argument("--resume", metavar="DIR",
                      help="Resume a previous scan from its output directory.")

    # Verbosity
    verb = p.add_argument_group("Output")
    verb.add_argument("--verbose", "-v", action="store_true",
                      help="Show informational messages.")
    verb.add_argument("--debug",   "-d", action="store_true",
                      help="Show debug messages (very noisy).")

    return p


# ─────────────────────────── Directory helpers ───────────────────────────────

def make_output_dirs(base: str, timestamp: str) -> tuple:
    """
    Create and return (scan_dir, raw_dir).
    scan_dir: output/<name>/
    raw_dir:  output/<name>/raw/
    """
    scan_dir = Path("output") / (base or timestamp)
    raw_dir  = scan_dir / "raw"
    scan_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    return scan_dir, raw_dir


def save_state(state: dict, scan_dir: Path) -> None:
    """Persist scan state to disk for --resume."""
    state_file = scan_dir / "state.json"
    state_file.write_text(json.dumps(state, indent=2, default=str), encoding="utf-8")


def load_state(resume_dir: str) -> tuple:
    """Load saved state from a previous run. Returns (state, scan_dir)."""
    scan_dir   = Path(resume_dir)
    state_file = scan_dir / "state.json"
    if not state_file.exists():
        raise FileNotFoundError(f"No state.json found in {resume_dir}. Cannot resume.")
    state = json.loads(state_file.read_text(encoding="utf-8"))
    return state, scan_dir


# ─────────────────────────── Progress helpers ────────────────────────────────

class ProgressTracker:
    """Simple progress tracker; uses tqdm if available, else plain print."""

    def __init__(self, total: int, desc: str = "Scanning"):
        self._total   = total
        self._current = 0
        self._bar     = None
        if HAS_TQDM:
            self._bar = tqdm(total=total, desc=desc, unit="task",
                             bar_format="{l_bar}{bar}| {n_fmt}/{total_fmt} [{elapsed}<{remaining}]",
                             colour="cyan")

    def advance(self, label: str = "") -> None:
        self._current += 1
        if self._bar:
            self._bar.set_postfix_str(label, refresh=True)
            self._bar.update(1)
        else:
            pct = int(self._current / self._total * 100)
            print(f"  [{pct:3d}%] {label}", flush=True)

    def close(self) -> None:
        if self._bar:
            self._bar.close()


# ─────────────────────────── Print helpers ───────────────────────────────────

def banner() -> None:
    print(f"""
{CYAN}{BOLD}
 █████╗ ██╗   ██╗████████╗ ██████╗       ██████╗ ███████╗ ██████╗ ██████╗ ███╗   ██╗
██╔══██╗██║   ██║╚══██╔══╝██╔═══██╗      ██╔══██╗██╔════╝██╔════╝██╔═══██╗████╗  ██║
███████║██║   ██║   ██║   ██║   ██║█████╗██████╔╝█████╗  ██║     ██║   ██║██╔██╗ ██║
██╔══██║██║   ██║   ██║   ██║   ██║╚════╝██╔══██╗██╔══╝  ██║     ██║   ██║██║╚██╗██║
██║  ██║╚██████╔╝   ██║   ╚██████╔╝      ██║  ██║███████╗╚██████╗╚██████╔╝██║ ╚████║
╚═╝  ╚═╝ ╚═════╝    ╚═╝    ╚═════╝       ╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚═╝  ╚═══╝
{RESET}{GRAY}      ███████╗██╗    ██╗ █████╗ ██████╗ ███╗   ███╗
      ██╔════╝██║    ██║██╔══██╗██╔══██╗████╗ ████║
      ███████╗██║ █╗ ██║███████║██████╔╝██╔████╔██║
      ╚════██║██║███╗██║██╔══██║██╔══██╗██║╚██╔╝██║
      ███████║╚███╔███╔╝██║  ██║██║  ██║██║ ╚═╝ ██║
      ╚══════╝ ╚══╝╚══╝ ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝     ╚═╝{RESET}
{YELLOW}  Automated Initial Reconnaissance — For Authorized Use Only{RESET}
""")


def print_section(title: str, icon: str = "►") -> None:
    width = 70
    line  = "─" * width
    print(f"\n{CYAN}{line}{RESET}")
    print(f"{CYAN}{icon} {BOLD}{title}{RESET}")
    print(f"{CYAN}{line}{RESET}")


def print_summary(scan_data: dict, scan_dir: Path, elapsed: float) -> None:
    """Print a colored summary table to the console."""
    nmap   = scan_data.get("nmap", {})
    vuln   = scan_data.get("searchsploit", {})
    ports  = nmap.get("open_ports", [])
    total_exploits = vuln.get("total_exploits", 0)

    print_section("SCAN SUMMARY", "✅")
    print(f"  {BOLD}Target:{RESET}         {CYAN}{scan_data.get('target')}{RESET}")
    print(f"  {BOLD}Hostname:{RESET}       {scan_data.get('nmap', {}).get('hostname') or 'N/A'}")
    print(f"  {BOLD}OS Guess:{RESET}       {scan_data.get('nmap', {}).get('os_guess') or 'N/A'}")
    print(f"  {BOLD}Open Ports:{RESET}     {GREEN}{len(ports)}{RESET}")
    print(f"  {BOLD}Exploits Found:{RESET} {RED if total_exploits else GREEN}{total_exploits}{RESET}")
    print(f"  {BOLD}Elapsed:{RESET}        {elapsed:.1f}s")
    print(f"  {BOLD}Output Dir:{RESET}     {scan_dir}")
    print()

    if ports:
        print(f"  {BOLD}{'PORT':<12}{'SERVICE':<18}{'PRODUCT':<28}{'VERSION'}{RESET}")
        for p in ports:
            port_str = f"{p['port']}/{p['protocol']}"
            exploits = [
                r for r in vuln.get("results", []) if r.get("port") == p["port"]
            ]
            has_exploits = any(r.get("exploits") for r in exploits)
            indicator = f" {RED}[{len(exploits[0]['exploits'])} exploits]{RESET}" if has_exploits and exploits else ""
            print(f"  {YELLOW}{port_str:<12}{RESET}{p['service']:<18}{p['product']:<28}"
                  f"{GRAY}{p['version']}{RESET}{indicator}")

    print()
    print(f"  {BOLD}Reports:{RESET}")
    for fname in sorted(scan_dir.glob("*")):
        if fname.suffix in (".html", ".json", ".csv"):
            print(f"    📄 {fname}")


# ─────────────────────────── Scan orchestrator ───────────────────────────────

def run_scan(target: str, profile: str, scan_dir: Path, raw_dir: Path,
             parallel: int, verbose: bool, demo: bool,
             state: dict) -> dict:
    """
    Orchestrate all scan modules.

    Runs nmap first (sequential), then dispatches web/smb/vuln in parallel
    where ports allow.

    Args:
        state: Optionally pre-filled dict from --resume (will skip completed steps).

    Returns:
        Fully populated scan_data dict.
    """
    # ── Phase 1: Nmap (must run first — gates all other modules) ──────────
    if "nmap" not in state:
        print_section("Phase 1 — Port Scan (nmap)", "🔍")
        nmap_result = run_nmap(
            target, profile, raw_dir,
            verbose=verbose, demo=demo
        )
        state["nmap"] = nmap_result
        save_state(state, scan_dir)
    else:
        logger.info("Resuming: nmap results already present.")

    open_ports  = state["nmap"].get("open_ports", [])
    http_open   = any(p["port"] in {80, 443, 8080, 8443, 8180} for p in open_ports)
    smb_open    = any(p["port"] in {139, 445} for p in open_ports)

    logger.info("Open ports: %s", [p["port"] for p in open_ports])
    logger.info("HTTP ports detected: %s  |  SMB ports detected: %s", http_open, smb_open)

    # ── Phase 2: Parallel secondary scans ─────────────────────────────────
    print_section("Phase 2 — Service Enumeration", "⚡")

    tasks = {}   # name → callable

    if http_open:
        if "whatweb" not in state:
            tasks["whatweb"] = lambda: run_whatweb(
                target, open_ports, raw_dir, verbose=verbose, demo=demo)
        if "nikto" not in state:
            tasks["nikto"] = lambda: run_nikto(
                target, open_ports, raw_dir, verbose=verbose, demo=demo)
    else:
        logger.info("No HTTP ports — skipping web scans.")

    if smb_open:
        if "smbclient" not in state:
            tasks["smbclient"] = lambda: run_smbclient(
                target, open_ports, raw_dir, verbose=verbose, demo=demo)
        if "enum4linux" not in state:
            tasks["enum4linux"] = lambda: run_enum4linux(
                target, open_ports, raw_dir, verbose=verbose, demo=demo)
    else:
        logger.info("No SMB ports — skipping SMB scans.")

    if "searchsploit" not in state:
        tasks["searchsploit"] = lambda: run_searchsploit(
            open_ports, raw_dir, verbose=verbose, demo=demo)

    # Default placeholders for skipped modules
    for key in ("whatweb", "nikto", "smbclient", "enum4linux", "searchsploit"):
        if key not in state and key not in tasks:
            state[key] = {"error": "Skipped — required ports not open."}

    progress = ProgressTracker(total=len(tasks) + 1, desc="Scanning")
    progress.advance("nmap ✓")   # already done

    if tasks:
        actual_workers = min(parallel, len(tasks))
        with ThreadPoolExecutor(max_workers=actual_workers) as pool:
            futures = {pool.submit(fn): name for name, fn in tasks.items()}
            for future in as_completed(futures):
                name = futures[future]
                try:
                    result = future.result()
                    state[name] = result
                    save_state(state, scan_dir)
                    progress.advance(f"{name} ✓")
                    logger.info("[%s] completed.", name)
                except Exception as exc:
                    logger.error("[%s] failed: %s", name, exc)
                    state[name] = {"error": str(exc)}
                    progress.advance(f"{name} ✗")

    progress.close()
    return state


# ─────────────────────────── Entry point ─────────────────────────────────────

def main() -> None:
    parser = build_parser()
    args   = parser.parse_args()

    # Validate: must have --target or --demo or --resume
    if not args.target and not args.demo and not args.resume:
        parser.error("Provide --target <IP/domain>, --demo, or --resume <dir>.")

    banner()

    # ── Timestamps and paths ──────────────────────────────────────────────
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target    = args.target or "demo-target"

    # ── Resume mode ───────────────────────────────────────────────────────
    if args.resume:
        print(f"{YELLOW}[RESUME] Loading state from {args.resume}{RESET}")
        try:
            state, scan_dir = load_state(args.resume)
        except FileNotFoundError as e:
            print(f"{RED}ERROR: {e}{RESET}")
            sys.exit(1)
        raw_dir = scan_dir / "raw"
        raw_dir.mkdir(exist_ok=True)
        target  = state.get("target", target)
        profile = state.get("meta", {}).get("profile", args.profile)
        print(f"{GREEN}[RESUME] Resuming scan of {target} (profile: {profile}){RESET}")
    else:
        state    = {}
        scan_dir, raw_dir = make_output_dirs(args.output or timestamp, timestamp)
        profile  = args.profile

    # ── Logging ───────────────────────────────────────────────────────────
    log_file = scan_dir / "recon.log"
    setup_logging(args.verbose, args.debug, log_file)
    logger.info("Auto-Recon Swarm starting. Target=%s Profile=%s Demo=%s",
                target, profile, args.demo)

    # ── Metadata ──────────────────────────────────────────────────────────
    if "meta" not in state:
        state["meta"] = {
            "profile":   profile,
            "timestamp": timestamp,
            "demo":      args.demo,
            "parallel":  args.parallel,
        }
    state["target"]    = target
    state["timestamp"] = timestamp

    print(f"\n  {BOLD}Target  :{RESET} {CYAN}{target}{RESET}")
    print(f"  {BOLD}Profile :{RESET} {profile}")
    print(f"  {BOLD}Workers :{RESET} {args.parallel}")
    print(f"  {BOLD}Output  :{RESET} {scan_dir}")
    print(f"  {BOLD}Demo    :{RESET} {args.demo}")
    if not args.demo:
        print(f"\n  {YELLOW}⚠  Only run against systems you are authorised to test.{RESET}")
    print()

    # ── Run scan ──────────────────────────────────────────────────────────
    t_start   = time.monotonic()
    scan_data = run_scan(
        target, profile, scan_dir, raw_dir,
        parallel=args.parallel,
        verbose=args.verbose,
        demo=args.demo,
        state=state,
    )
    elapsed = time.monotonic() - t_start

    # ── Generate reports ──────────────────────────────────────────────────
    print_section("Phase 3 — Report Generation", "📝")

    html_path = scan_dir / f"report_{timestamp}.html"
    json_path = scan_dir / f"report_{timestamp}.json"
    csv_path  = scan_dir / f"report_{timestamp}.csv"

    generate_html(scan_data, html_path, raw_dir)
    generate_json(scan_data, json_path)
    generate_csv(scan_data, csv_path)

    print(f"  {GREEN}✓{RESET} HTML : {html_path}")
    print(f"  {GREEN}✓{RESET} JSON : {json_path}")
    print(f"  {GREEN}✓{RESET} CSV  : {csv_path}")

    # ── Summary ───────────────────────────────────────────────────────────
    print_summary(scan_data, scan_dir, elapsed)
    logger.info("Scan complete in %.1fs. Reports in %s", elapsed, scan_dir)


if __name__ == "__main__":
    main()
