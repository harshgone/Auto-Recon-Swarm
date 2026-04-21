# Auto-Recon Swarm 🛡

**Automated initial reconnaissance for authorized penetration testing on Kali Linux.**

> ⚠️ **Legal notice**: This tool is intended exclusively for authorized security assessments.
> Unauthorized scanning of systems you do not own or have explicit written permission to test
> is illegal. The author accepts no liability for misuse.

---

## Features

| Feature | Details |
|---|---|
| **Port scanning** | nmap with XML parsing (quick: top 100 / full: 1–65535) |
| **Web tech detection** | WhatWeb against all open HTTP/HTTPS ports |
| **Web vuln scan** | Nikto against all open HTTP/HTTPS ports |
| **SMB enumeration** | smbclient (share list) + enum4linux / enum4linux-ng |
| **Exploit search** | searchsploit queried per service/version |
| **Parallel execution** | ThreadPoolExecutor — configurable worker count |
| **Conditional scanning** | Web tools only run if HTTP ports open; SMB only if 139/445 open |
| **Progress bar** | tqdm with ETA |
| **Resume** | `--resume` picks up from last saved state |
| **Demo mode** | `--demo` uses embedded Metasploitable 2 data — no live target needed |
| **Reports** | HTML (collapsible, dark theme), JSON, CSV |
| **Raw output** | All tool outputs saved in `output/<run>/raw/` |

---

## Installation

### Prerequisites (Kali Linux — most are pre-installed)

```bash
sudo apt update
sudo apt install -y nmap whatweb nikto smbclient enum4linux exploitdb
```

> **enum4linux-ng** (preferred over enum4linux):
> ```bash
> sudo apt install -y enum4linux-ng
> ```

### Python setup

```bash
# Clone / copy the project
cd auto-recon-swarm

# Install Python deps (only tqdm is required beyond stdlib)
pip install -r requirements.txt
```

---

## Usage

### Quick start

```bash
# Fast scan — top 100 ports
python recon.py --target 192.168.1.10

# Full scan — all 65535 ports, 6 parallel workers
python recon.py --target 192.168.1.10 --profile full --parallel 6

# Named output directory
python recon.py --target 192.168.1.10 --output acme_pentest

# Verbose (see info messages)
python recon.py --target 192.168.1.10 --verbose

# Debug (very noisy — shows every subprocess line)
python recon.py --target 192.168.1.10 --debug

# Demo mode — no live target needed, uses embedded Metasploitable 2 data
python recon.py --demo

# Resume an interrupted scan
python recon.py --resume output/20240610_143000/
```

### All options

```
usage: recon.py [-h] [--target IP/DOMAIN] [--profile {quick,full}]
                [--parallel N] [--output NAME]
                [--demo] [--resume DIR]
                [--verbose] [--debug]

Target:
  --target, -t    Target IP address or domain name
  --profile       quick (top 100 ports) | full (all 65535)  [default: quick]

Execution:
  --parallel N    Thread pool size  [default: 4]
  --output NAME   Output directory name (under output/)

Special modes:
  --demo          Run with embedded demo data (Metasploitable 2)
  --resume DIR    Resume from a previous scan directory

Output:
  --verbose, -v   Show informational messages
  --debug,   -d   Show debug messages
```

---

## Output structure

```
output/
└── 20240610_143022/           # timestamped run directory
    ├── raw/
    │   ├── nmap.xml
    │   ├── nmap_stdout.txt
    │   ├── whatweb_80.json
    │   ├── nikto_80.txt
    │   ├── smbclient.txt
    │   ├── enum4linux.txt
    │   └── searchsploit_*.json
    ├── report_20240610_143022.html    ← open in browser
    ├── report_20240610_143022.json    ← machine-parseable
    ├── report_20240610_143022.csv     ← spreadsheet summary
    ├── state.json                     ← resume checkpoint
    └── recon.log                      ← full debug log
```

---

## Project structure

```
auto-recon-swarm/
├── recon.py              # Main entry point — CLI, orchestration, reporting
├── modules/
│   ├── __init__.py
│   ├── scanner.py        # nmap wrapper + XML parser
│   ├── web.py            # WhatWeb + Nikto wrappers
│   ├── smb.py            # smbclient + enum4linux wrappers
│   ├── vuln.py           # searchsploit wrapper
│   └── report.py         # HTML / JSON / CSV generation
├── requirements.txt
└── README.md
```

---

## Demo mode example

Run without any live target:

```bash
python recon.py --demo
```

This uses a pre-baked Metasploitable 2 nmap XML and synthetic tool outputs to
generate full reports immediately — useful for testing the tool itself or
demonstrating it in a classroom setting.

---

## Extending the tool

Each module follows the same contract:

```python
def run_<module>(target, open_ports, output_dir, verbose, demo) -> dict:
    """Returns structured data dict. Never raises — returns error key on failure."""
```

To add a new scanner (e.g. `gobuster`):

1. Create `modules/gobuster.py` implementing `run_gobuster(...)`.
2. Import it in `recon.py`.
3. Add a conditional check (e.g. HTTP ports open).
4. Submit it to the `ThreadPoolExecutor` task dict.
5. Add a section to `report.py`.

---

## Tested on

- Kali Linux 2024.x (rolling)
- Python 3.11+
- nmap 7.94, nikto 2.1.6, whatweb 0.5.5, smbclient 4.x, enum4linux 0.9.x

---

## License

MIT — see individual tool licenses for nmap, nikto, etc.
