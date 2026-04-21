"""
report.py — Report generation for Auto-Recon Swarm.

Produces:
  • HTML   — collapsible sections, color-coded severity, download links
  • JSON   — complete raw scan data
  • CSV    — summary table (port, service, exploits)
"""

import csv
import json
import logging
import html as _html
from datetime import datetime
from pathlib import Path

logger = logging.getLogger("recon.report")


# ──────────────────────────── HTML template ───────────────────────────────────
# Embedded Jinja2-free template written with Python f-strings so we have
# zero hard dependencies beyond the standard library.

_HTML_HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Auto-Recon Swarm — {target}</title>
  <style>
    :root {{
      --bg:        #0d1117;
      --surface:   #161b22;
      --border:    #30363d;
      --text:      #c9d1d9;
      --muted:     #8b949e;
      --accent:    #58a6ff;
      --green:     #3fb950;
      --yellow:    #d29922;
      --red:       #f85149;
      --orange:    #db6d28;
      --purple:    #bc8cff;
    }}
    * {{ box-sizing: border-box; margin: 0; padding: 0; }}
    body {{
      background: var(--bg);
      color: var(--text);
      font-family: 'Segoe UI', system-ui, -apple-system, sans-serif;
      font-size: 14px;
      line-height: 1.6;
      padding: 0 1rem 4rem;
    }}
    /* ── Header ── */
    header {{
      background: var(--surface);
      border-bottom: 1px solid var(--border);
      padding: 1.5rem 2rem;
      position: sticky; top: 0; z-index: 100;
      display: flex; align-items: center; gap: 1rem;
    }}
    header h1 {{ font-size: 1.4rem; color: var(--accent); flex: 1; }}
    .badge {{
      padding: .2rem .7rem;
      border-radius: 99px;
      font-size: .75rem;
      font-weight: 600;
      border: 1px solid currentColor;
    }}
    .badge-green  {{ color: var(--green); }}
    .badge-red    {{ color: var(--red); }}
    .badge-yellow {{ color: var(--yellow); }}
    /* ── Layout ── */
    .container {{ max-width: 1200px; margin: 0 auto; padding-top: 2rem; }}
    /* ── Info grid ── */
    .info-grid {{
      display: grid;
      grid-template-columns: repeat(auto-fill, minmax(220px, 1fr));
      gap: 1rem;
      margin-bottom: 2rem;
    }}
    .info-card {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 1rem 1.2rem;
    }}
    .info-card .label {{ color: var(--muted); font-size: .75rem; text-transform: uppercase; letter-spacing:.05em; }}
    .info-card .value {{ font-size: 1.1rem; font-weight: 600; color: var(--text); margin-top: .2rem; }}
    /* ── Section ── */
    .section {{
      background: var(--surface);
      border: 1px solid var(--border);
      border-radius: 8px;
      margin-bottom: 1.5rem;
      overflow: hidden;
    }}
    .section-header {{
      display: flex;
      align-items: center;
      gap: .6rem;
      padding: .9rem 1.2rem;
      cursor: pointer;
      user-select: none;
      background: var(--surface);
      border-bottom: 1px solid transparent;
      transition: background .15s;
    }}
    .section-header:hover {{ background: #1c2128; }}
    .section-header.open {{ border-bottom-color: var(--border); }}
    .section-header h2 {{ font-size: 1rem; font-weight: 600; flex: 1; }}
    .chevron {{ transition: transform .2s; color: var(--muted); }}
    .section-header.open .chevron {{ transform: rotate(90deg); }}
    .section-body {{ padding: 1rem 1.2rem; display: none; }}
    .section-header.open + .section-body {{ display: block; }}
    /* ── Tables ── */
    table {{ width: 100%; border-collapse: collapse; font-size: .9rem; }}
    th {{ text-align: left; color: var(--muted); font-weight: 600;
          padding: .5rem .8rem; border-bottom: 1px solid var(--border); font-size: .75rem;
          text-transform: uppercase; letter-spacing: .04em; }}
    td {{ padding: .55rem .8rem; border-bottom: 1px solid var(--border); vertical-align: top; }}
    tr:last-child td {{ border-bottom: none; }}
    tr:hover td {{ background: rgba(255,255,255,.02); }}
    .port-num  {{ font-family: monospace; color: var(--purple); font-weight: 700; }}
    .svc-name  {{ color: var(--accent); }}
    .version   {{ color: var(--muted); font-size: .85em; }}
    /* ── Severity colors ── */
    .crit {{ color: var(--red); }}
    .high {{ color: var(--orange); }}
    .med  {{ color: var(--yellow); }}
    .low  {{ color: var(--green); }}
    .info-clr {{ color: var(--muted); }}
    /* ── Exploit cards ── */
    .exploit-list {{ list-style: none; }}
    .exploit-list li {{
      background: #0d1117;
      border: 1px solid var(--border);
      border-radius: 6px;
      padding: .6rem 1rem;
      margin-bottom: .5rem;
      display: flex;
      gap: .8rem;
      align-items: flex-start;
    }}
    .exploit-id {{
      background: var(--red);
      color: #fff;
      font-size: .7rem;
      font-weight: 700;
      padding: .15rem .5rem;
      border-radius: 4px;
      white-space: nowrap;
      margin-top: .15rem;
    }}
    .exploit-title {{ flex: 1; }}
    .exploit-path {{ font-size: .78rem; color: var(--muted); font-family: monospace; }}
    /* ── Nikto lines ── */
    .nikto-line {{
      font-family: monospace;
      font-size: .82rem;
      padding: .3rem 0;
      border-bottom: 1px solid var(--border);
      color: var(--yellow);
    }}
    .nikto-line:last-child {{ border-bottom: none; }}
    /* ── SMB ── */
    .share-row td:first-child {{ font-family: monospace; color: var(--green); }}
    /* ── Download links ── */
    .dl-links {{ display: flex; flex-wrap: wrap; gap: .6rem; margin-top: .5rem; }}
    .dl-link {{
      display: inline-flex; align-items: center; gap: .4rem;
      background: #161b22;
      border: 1px solid var(--border);
      color: var(--accent);
      padding: .4rem .9rem;
      border-radius: 6px;
      text-decoration: none;
      font-size: .82rem;
      transition: border-color .15s;
    }}
    .dl-link:hover {{ border-color: var(--accent); }}
    /* ── Empty state ── */
    .empty {{ color: var(--muted); font-style: italic; padding: .5rem 0; }}
    /* ── Footer ── */
    footer {{
      text-align: center;
      color: var(--muted);
      font-size: .78rem;
      margin-top: 3rem;
      padding-top: 1.5rem;
      border-top: 1px solid var(--border);
    }}
  </style>
</head>
<body>
"""

_HTML_SCRIPT = """\
<script>
document.querySelectorAll('.section-header').forEach(function(hdr) {
  hdr.addEventListener('click', function() {
    hdr.classList.toggle('open');
  });
  // Default open first 3 sections
});
// Auto-open first 3 sections
var hdrs = document.querySelectorAll('.section-header');
for (var i = 0; i < Math.min(3, hdrs.length); i++) {
  hdrs[i].classList.add('open');
}
</script>
"""


def _e(text: str) -> str:
    """HTML-escape a value for safe embedding."""
    return _html.escape(str(text) if text is not None else "")


def _section(title: str, icon: str, body: str, badge: str = "", badge_cls: str = "") -> str:
    badge_html = ""
    if badge:
        badge_html = f'<span class="badge badge-{badge_cls}">{_e(badge)}</span>'
    return f"""
<div class="section">
  <div class="section-header">
    <span>{icon}</span>
    <h2>{_e(title)}</h2>
    {badge_html}
    <span class="chevron">▶</span>
  </div>
  <div class="section-body">
    {body}
  </div>
</div>
"""


# ─────────────────────────── HTML builder ────────────────────────────────────

def generate_html(scan_data: dict, output_path: Path, raw_dir: Path) -> Path:
    """
    Build a full HTML report from the aggregated scan_data dict.

    Args:
        scan_data:   Aggregated results from all modules.
        output_path: Where to write the .html file.
        raw_dir:     Path to raw/ directory for download links.

    Returns:
        Path to the written HTML file.
    """
    target    = scan_data.get("target", "unknown")
    timestamp = scan_data.get("timestamp", datetime.now().isoformat())
    nmap      = scan_data.get("nmap", {})
    web_ww    = scan_data.get("whatweb", {})
    web_nk    = scan_data.get("nikto", {})
    smb_sc    = scan_data.get("smbclient", {})
    smb_e4l   = scan_data.get("enum4linux", {})
    vuln      = scan_data.get("searchsploit", {})
    meta      = scan_data.get("meta", {})

    open_ports   = nmap.get("open_ports", [])
    total_ports  = len(open_ports)
    total_exploits = vuln.get("total_exploits", 0)

    # ── Build port table ──────────────────────────────────────────────────
    if open_ports:
        rows = "".join(
            f"""<tr>
              <td class="port-num">{_e(p['port'])}/{_e(p['protocol'])}</td>
              <td class="svc-name">{_e(p['service'])}</td>
              <td>{_e(p['product'])}</td>
              <td class="version">{_e(p['version'])}</td>
              <td><span class="badge badge-green">OPEN</span></td>
            </tr>"""
            for p in open_ports
        )
        port_table = f"""<table>
          <thead><tr>
            <th>Port</th><th>Service</th><th>Product</th><th>Version</th><th>State</th>
          </tr></thead>
          <tbody>{rows}</tbody>
        </table>"""
    else:
        port_table = '<p class="empty">No open ports found.</p>'

    # ── Exploit section ───────────────────────────────────────────────────
    exploit_blocks = []
    for r in vuln.get("results", []):
        if not r["exploits"]:
            continue
        items = "".join(
            f"""<li>
              <span class="exploit-id">EDB-{_e(ex['id'])}</span>
              <div>
                <div class="exploit-title">{_e(ex['title'])}</div>
                <div class="exploit-path">{_e(ex['path'])}</div>
              </div>
            </li>"""
            for ex in r["exploits"]
        )
        exploit_blocks.append(f"""
          <p style="color:var(--muted);font-size:.82rem;margin-bottom:.4rem;">
            Port {_e(r['port'])} — {_e(r['service'])}
            (query: <code>{_e(r['query'])}</code>)
          </p>
          <ul class="exploit-list">{items}</ul>
        """)

    exploit_body = "".join(exploit_blocks) if exploit_blocks else \
        '<p class="empty">No exploits found.</p>'

    # ── WhatWeb section ───────────────────────────────────────────────────
    ww_rows = []
    for finding in web_ww.get("findings", []):
        url = finding.get("url", "")
        for tech in finding.get("technologies", []):
            ver = f" {tech['version']}" if tech.get("version") else ""
            ww_rows.append(f"""<tr>
              <td><a href="{_e(url)}" target="_blank" style="color:var(--accent)">{_e(url)}</a></td>
              <td class="svc-name">{_e(tech['name'])}{_e(ver)}</td>
              <td class="version">{_e(tech.get('detail',''))}</td>
            </tr>""")

    ww_body = f"""<table>
      <thead><tr><th>URL</th><th>Technology</th><th>Detail</th></tr></thead>
      <tbody>{''.join(ww_rows)}</tbody>
    </table>""" if ww_rows else '<p class="empty">WhatWeb did not run or found nothing.</p>'

    # ── Nikto section ────────────────────────────────────────────────────
    nikto_blocks = []
    for finding in web_nk.get("findings", []):
        port = finding.get("port")
        vulns_list = finding.get("vulnerabilities", [])
        if not vulns_list:
            continue
        lines = "".join(
            f'<div class="nikto-line">{_e(v)}</div>' for v in vulns_list
        )
        nikto_blocks.append(f"""
          <p style="color:var(--muted);font-size:.82rem;margin:.4rem 0;">{_e(f'Port {port}')}</p>
          {lines}
        """)

    nikto_body = "".join(nikto_blocks) if nikto_blocks else \
        '<p class="empty">Nikto did not run or found nothing.</p>'

    # ── SMB sections ─────────────────────────────────────────────────────
    share_rows = "".join(
        f"""<tr class="share-row">
          <td>{_e(s['name'])}</td>
          <td>{_e(s['type'])}</td>
          <td class="version">{_e(s['comment'])}</td>
        </tr>"""
        for s in smb_sc.get("shares", [])
    )
    smb_body = f"""<table>
      <thead><tr><th>Share</th><th>Type</th><th>Comment</th></tr></thead>
      <tbody>{share_rows}</tbody>
    </table>""" if share_rows else '<p class="empty">No SMB shares found or SMB not scanned.</p>'

    # enum4linux users table
    user_rows = "".join(
        f"""<tr>
          <td style="font-family:monospace;color:var(--green)">{_e(u['username'])}</td>
          <td class="version">{_e(u.get('uid',''))}</td>
          <td class="version">{_e(u.get('comment',''))}</td>
        </tr>"""
        for u in smb_e4l.get("users", [])
    )
    e4l_body = f"""
      <p style="color:var(--muted);font-size:.82rem;margin-bottom:.6rem;">
        Workgroup: <strong style="color:var(--text)">{_e(smb_e4l.get('workgroup','?'))}</strong>
      </p>
      {"<table><thead><tr><th>Username</th><th>UID</th><th>Comment</th></tr></thead><tbody>" + user_rows + "</tbody></table>" if user_rows else '<p class="empty">No users enumerated.</p>'}
    """

    # ── Download links ────────────────────────────────────────────────────
    raw_files = sorted(raw_dir.glob("*")) if raw_dir.exists() else []
    dl_links = "".join(
        f'<a class="dl-link" href="raw/{_e(f.name)}" download>📄 {_e(f.name)}</a>'
        for f in raw_files if f.is_file()
    )
    dl_body = (
        f'<div class="dl-links">{dl_links}</div>' if dl_links
        else '<p class="empty">No raw files available.</p>'
    )

    # ── Info cards ────────────────────────────────────────────────────────
    os_guess = _e(nmap.get("os_guess") or "Unknown")
    hostname = _e(nmap.get("hostname") or target)
    profile  = _e(meta.get("profile", "quick"))

    info_grid = f"""
    <div class="info-grid">
      <div class="info-card">
        <div class="label">Target</div>
        <div class="value">{_e(target)}</div>
      </div>
      <div class="info-card">
        <div class="label">Hostname</div>
        <div class="value">{hostname}</div>
      </div>
      <div class="info-card">
        <div class="label">OS Guess</div>
        <div class="value">{os_guess}</div>
      </div>
      <div class="info-card">
        <div class="label">Open Ports</div>
        <div class="value" style="color:var(--green)">{total_ports}</div>
      </div>
      <div class="info-card">
        <div class="label">Exploits Found</div>
        <div class="value" style="color:{'var(--red)' if total_exploits > 0 else 'var(--green)'}">{total_exploits}</div>
      </div>
      <div class="info-card">
        <div class="label">Scan Profile</div>
        <div class="value">{profile}</div>
      </div>
      <div class="info-card">
        <div class="label">Scan Time</div>
        <div class="value" style="font-size:.85rem">{_e(timestamp)}</div>
      </div>
    </div>
    """

    exploit_badge     = str(total_exploits) if total_exploits else "0"
    exploit_badge_cls = "red" if total_exploits > 0 else "green"

    # ── Assemble page ─────────────────────────────────────────────────────
    body = f"""
    <header>
      <h1>🛡 Auto-Recon Swarm</h1>
      <span class="badge badge-yellow">{_e(target)}</span>
      <span class="badge badge-{'green' if total_ports > 0 else 'red'}">{total_ports} ports open</span>
    </header>
    <div class="container">
      {info_grid}
      {_section('Open Ports & Services', '🔍', port_table)}
      {_section('Vulnerability Search (searchsploit)', '💣', exploit_body,
                badge=exploit_badge, badge_cls=exploit_badge_cls)}
      {_section('Web Technology (WhatWeb)', '🌐', ww_body)}
      {_section('Web Vulnerabilities (Nikto)', '⚠️', nikto_body)}
      {_section('SMB Shares (smbclient)', '📁', smb_body)}
      {_section('SMB Enumeration (enum4linux)', '👤', e4l_body)}
      {_section('Raw Tool Output Downloads', '📦', dl_body)}
    </div>
    <footer>
      Generated by Auto-Recon Swarm &nbsp;|&nbsp; {_e(timestamp)} &nbsp;|&nbsp;
      For authorized use only.
    </footer>
    {_HTML_SCRIPT}
    </body></html>
    """

    output_path.write_text(
        _HTML_HEAD.format(target=_e(target)) + body,
        encoding="utf-8"
    )
    logger.info("HTML report written to %s", output_path)
    return output_path


# ─────────────────────────── JSON report ─────────────────────────────────────

def generate_json(scan_data: dict, output_path: Path) -> Path:
    """Serialize the complete scan_data dict to a JSON file."""
    output_path.write_text(
        json.dumps(scan_data, indent=2, default=str),
        encoding="utf-8"
    )
    logger.info("JSON report written to %s", output_path)
    return output_path


# ─────────────────────────── CSV report ──────────────────────────────────────

def generate_csv(scan_data: dict, output_path: Path) -> Path:
    """Write a flat CSV summary: one row per open port."""
    nmap        = scan_data.get("nmap", {})
    vuln        = scan_data.get("searchsploit", {})
    open_ports  = nmap.get("open_ports", [])
    target      = scan_data.get("target", "")

    # Build quick lookup: port → [exploit titles]
    exploit_map: dict = {}
    for r in vuln.get("results", []):
        exploit_map[r["port"]] = [ex["title"] for ex in r.get("exploits", [])]

    fieldnames = [
        "target", "port", "protocol", "service",
        "product", "version", "exploit_count", "exploit_titles",
    ]

    with output_path.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=fieldnames)
        writer.writeheader()
        for p in open_ports:
            port_num = p["port"]
            exploits = exploit_map.get(port_num, [])
            writer.writerow({
                "target":         target,
                "port":           port_num,
                "protocol":       p.get("protocol", "tcp"),
                "service":        p.get("service", ""),
                "product":        p.get("product", ""),
                "version":        p.get("version", ""),
                "exploit_count":  len(exploits),
                "exploit_titles": " | ".join(exploits),
            })

    logger.info("CSV report written to %s", output_path)
    return output_path
