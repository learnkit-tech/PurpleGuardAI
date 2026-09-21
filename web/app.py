"""PurpleGuardAI Web Dashboard.

Serves security reports, hacker pipeline results, and remediation
status through a browser-based interface.

Run directly:   python web/app.py
Or via Freebuff preview (binds to 0.0.0.0 on PORT).
"""

import glob
import json
import os
import subprocess
import sys
import threading
from collections import Counter
from pathlib import Path

# Ensure the project root is on the import path so scanner/hacker
# modules are importable when the web app is launched from any cwd.
PROJECT_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(PROJECT_ROOT))

from flask import Flask, jsonify, request

app = Flask(__name__)

from scanner.rules.registry import RULES
from scanner.remediation.patcher import CodePatcher


# ─── HTML fragments ─────────────────────────────────────────

HEAD = """\
<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} — PurpleGuardAI</title>
<link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700&display=swap" rel="stylesheet">
<script src="https://cdn.tailwindcss.com"></script>
<script>
tailwind.config={{
  theme:{{
    extend:{{
      fontFamily:{{sans:['Inter','system-ui','sans-serif']}},
      colors:{{
        brand:{{50:'#faf5ff',100:'#f3e8ff',200:'#e9d5ff',300:'#d8b4fe',
                400:'#c084fc',500:'#a855f7',600:'#9333ea',700:'#7e22ce',
                800:'#6b21a8',900:'#581c87'}},
      }}
    }}
  }}
}}
</script>
</head>
<body class="bg-gray-950 text-gray-100 font-sans min-h-screen">

<nav class="bg-gray-900 border-b border-gray-800 px-4 sm:px-6 py-3">
  <div class="max-w-7xl mx-auto flex items-center justify-between">
    <a href="/" class="flex items-center gap-2 text-brand-400 font-bold text-base sm:text-lg tracking-tight">
      <svg class="w-5 h-5 sm:w-6 sm:h-6" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
        <path stroke-linecap="round" stroke-linejoin="round" d="M9 12l2 2 4-4m5.618-4.016A11.955 11.955 0 0112 2.944a11.955 11.955 0 01-8.618 3.04A12.02 12.02 0 003 9c0 5.591 3.824 10.29 9 11.622 5.176-1.332 9-6.03 9-11.622 0-1.042-.133-2.052-.382-3.016z"/>
      </svg>
      <span class="hidden sm:inline">PurpleGuard</span>
      <span class="sm:hidden">PG</span>
    </a>
    <div class="flex items-center gap-4 sm:gap-6 text-sm text-gray-400">
      <a href="/" class="hover:text-white transition">Dashboard</a>
      <a href="/reports" class="hover:text-white transition">Reports</a>
      <a href="/pipeline" class="hover:text-white transition">Assessment</a>
    </div>
  </div>
</nav>

<main class="max-w-7xl mx-auto px-4 sm:px-6 py-6 sm:py-8">
"""

TAIL = """\
</main>
<footer class="border-t border-gray-800 mt-16 py-6 text-center text-xs text-gray-600">
  PurpleGuardAI — Autonomous Security Scanner
</footer>
</body>
</html>
"""


# ─── Helpers ────────────────────────────────────────────────

def _page(title, body):
    return HEAD.format(title=title) + body + TAIL


def _load_json(filename):
    path = PROJECT_ROOT / "reports" / filename
    if not path.exists():
        return None
    with open(path) as f:
        return json.load(f)


def _save_json(filename, data):
    reports_dir = PROJECT_ROOT / "reports"
    os.makedirs(reports_dir, exist_ok=True)
    with open(reports_dir / filename, "w") as f:
        json.dump(data, f, indent=4)


def _list_reports():
    reports_dir = PROJECT_ROOT / "reports"
    if not reports_dir.exists():
        return []
    reports = []
    for path in sorted(reports_dir.glob("*.json"), key=os.path.getmtime, reverse=True):
        size = path.stat().st_size
        size_str = f"{size / 1024:.1f} KB" if size > 1024 else f"{size} B"
        title = path.stem.replace("_", " ").title()
        reports.append({"name": path.name, "title": title, "size": size_str})
    return reports


def _badge(text, color):
    """Small colored badge."""
    cls = {
        "green": "bg-emerald-500/10 text-emerald-400",
        "red": "bg-red-500/10 text-red-400",
        "yellow": "bg-yellow-500/10 text-yellow-400",
        "blue": "bg-blue-500/10 text-blue-400",
        "gray": "bg-gray-500/10 text-gray-400",
        "purple": "bg-brand-500/10 text-brand-400",
    }.get(color, "bg-gray-500/10 text-gray-400")
    return f'<span class="inline-flex px-2 py-0.5 rounded text-xs font-medium {cls}">{text}</span>'


def _step_icon(done, current=False):
    if done:
        return '<span class="w-6 h-6 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs shrink-0">✓</span>'
    if current:
        return '<span class="w-6 h-6 rounded-full bg-brand-500/20 text-brand-400 flex items-center justify-center text-xs shrink-0 animate-pulse">●</span>'
    return '<span class="w-6 h-6 rounded-full bg-gray-800 text-gray-600 flex items-center justify-center text-xs shrink-0">○</span>'


# ─── Dashboard ──────────────────────────────────────────────

@app.route("/")
def index():
    scan = _load_json("scan_report.json")
    hack = _load_json("orchestrator_report.json")

    findings = scan.get("findings", []) if scan else []
    severity = Counter(f.get("severity", "UNKNOWN") for f in findings)
    autofix_ids = CodePatcher.AUTO_FIXABLE

    # --- Findings table rows ---
    findings_rows = ""
    for f in findings:
        sev_cls = {
            "CRITICAL": "bg-red-500/10 text-red-400",
            "HIGH": "bg-orange-500/10 text-orange-400",
            "MEDIUM": "bg-yellow-500/10 text-yellow-400",
        }.get(f.get("severity"), "bg-gray-500/10 text-gray-400")
        fix_badge = (
            '<span class="text-emerald-400 text-xs">✓ Yes</span>'
            if f.get("id") in autofix_ids
            else '<span class="text-gray-500 text-xs">Manual</span>'
        )
        findings_rows += f"""
        <tr class="border-b border-gray-800/50 hover:bg-gray-800/30 transition">
          <td class="px-4 py-3 font-mono text-brand-400">{f.get('id','')}</td>
          <td class="px-4 py-3 text-white">{f.get('name','')}</td>
          <td class="px-4 py-3 text-gray-400 font-mono text-xs">{f.get('file','')}</td>
          <td class="px-4 py-3 text-gray-400">{f.get('line','')}</td>
          <td class="px-4 py-3"><span class="inline-flex px-2 py-0.5 rounded text-xs font-medium {sev_cls}">{f.get('severity','')}</span></td>
          <td class="px-4 py-3">{fix_badge}</td>
        </tr>"""

    # --- Severity bars ---
    severity_bars = ""
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        count = severity.get(sev, 0)
        if count == 0:
            continue
        pct = int(count / len(findings) * 100) if findings else 0
        bar_cls = {"CRITICAL": "bg-red-500", "HIGH": "bg-orange-500", "MEDIUM": "bg-yellow-500"}.get(sev, "bg-gray-500")
        label_cls = {"CRITICAL": "text-red-400", "HIGH": "text-orange-400", "MEDIUM": "text-yellow-400"}.get(sev, "text-gray-400")
        severity_bars += f"""
        <div class="flex items-center gap-3">
          <span class="w-20 text-sm font-medium {label_cls}">{sev}</span>
          <div class="flex-1 bg-gray-800 rounded-full h-3 overflow-hidden">
            <div class="h-full rounded-full {bar_cls}" style="width:{pct}%"></div>
          </div>
          <span class="w-8 text-right text-sm text-gray-400">{count}</span>
        </div>"""

    # --- Security assessment section (from orchestrator) ---
    assessment_section = ""
    if hack:
        recon = hack.get("recon", {})
        validation = hack.get("validation", [])
        confirmed = [v for v in validation if v.get("validated")]
        plans = hack.get("plans", [])
        rem = hack.get("remediation", {})
        rem_result = rem.get("result", {})
        applied = [r for r in rem_result.get("results", []) if r.get("status") == "APPLIED"]
        requires_review = rem.get("requires_review", [])
        hv = hack.get("hacker_verification", {})
        reattack = hv.get("results", [])
        blocked = [r for r in reattack if r.get("blocked")]
        verification = hack.get("verification", {})
        verdict = verification.get("verdict", {})
        static_scan = verification.get("static_scan", {})
        tests = verification.get("tests", {})
        status = hack.get("status", "UNKNOWN")

        verdict_color = "emerald" if status == "SECURITY_VERIFIED" else "red"
        verdict_bg = f"bg-{verdict_color}-500/10 text-{verdict_color}-400 border-{verdict_color}-500/30"

        # --- Evidence steps ---
        evidence_steps = [
            ("Discovery", f"{recon.get('files_analyzed', 0)} files", f"{recon.get('attack_surfaces', 0)} surfaces", f"{recon.get('attack_paths', 0)} attack paths", bool(recon)),
            ("Validation", f"{len(plans)} planned", f"{len(confirmed)}/{len(plans)} confirmed", "", bool(validation)),
            ("Remediation", f"{rem.get('available', 0)} auto-fixable", f"{len(requires_review)} manual", f"{len(applied)} applied", bool(rem_result)),
            ("Rescan", "PASS" if static_scan.get("passed") else "FAIL", f"{len(static_scan.get('remaining_original_findings', []))} remaining", "", "passed" in static_scan),
            ("Tests", "PASS" if tests.get("passed") else "FAIL", "", "", "passed" in tests),
            ("Re-attack", f"{len(blocked)}/{len(reattack)} blocked", "", "", bool(reattack)),
        ]

        steps_html = ""
        for label, main, sub1, sub2, done in evidence_steps:
            sub_parts = f'<span class="text-gray-500 text-xs">{sub1}</span>' if sub1 else ""
            if sub2:
                sub_parts += f' <span class="text-gray-600 text-xs">· {sub2}</span>'
            steps_html += f"""
            <div class="flex items-start gap-3 py-3">
              {_step_icon(done)}
              <div class="flex-1 min-w-0">
                <div class="flex items-center gap-2 flex-wrap">
                  <span class="font-medium text-white text-sm">{label}</span>
                  <span class="text-gray-400 text-xs">{main}</span>
                </div>
                {sub_parts}
              </div>
            </div>"""

        # --- Per-finding validation rows ---
        finding_detail_rows = ""
        for v in validation:
            v_status = "CONFIRMED" if v.get("validated") else "NOT CONFIRMED"
            v_color = "green" if v.get("validated") else "gray"
            finding_detail_rows += f"""
            <div class="flex items-center gap-3 py-2 text-sm">
              {_badge(v_status, v_color)}
              <span class="font-mono text-brand-400">{v.get('path_id','')}</span>
              <span class="text-white">{v.get('category','')}</span>
              <span class="text-gray-600">→</span>
              <span class="text-gray-500">{v.get('validator','')}</span>
            </div>"""

        assessment_section = f"""
        <div class="bg-gray-900 rounded-xl border border-gray-800 mb-8">
          <div class="p-5 border-b border-gray-800 flex items-center justify-between flex-wrap gap-3">
            <h2 class="text-lg font-semibold text-white">Security Assessment</h2>
            <span class="text-sm px-3 py-1 rounded-full font-medium {verdict_bg}">{status}</span>
          </div>
          <div class="p-5">
            <div class="grid grid-cols-1 lg:grid-cols-2 gap-6">
              <!-- Evidence steps -->
              <div>
                <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider mb-3">Verification Evidence</h3>
                <div class="divide-y divide-gray-800/50">{steps_html}</div>
              </div>
              <!-- Validation details -->
              <div>
                <h3 class="text-sm font-medium text-gray-400 uppercase tracking-wider mb-3">Attack Validation</h3>
                <div class="space-y-1">{finding_detail_rows}</div>
              </div>
            </div>
          </div>
        </div>"""

    # --- Hacker pipeline summary (compact) ---
    hacker_section = ""
    if hack and not assessment_section:
        # Fallback if no full assessment data
        recon = hack.get("recon", {})
        validation = hack.get("validation", [])
        confirmed = [v for v in validation if v.get("validated")]
        hv = hack.get("hacker_verification", {})
        reattack = hv.get("results", [])
        blocked = [r for r in reattack if r.get("blocked")]

        results_rows = ""
        for r in reattack:
            icon = (
                '<span class="w-5 h-5 rounded-full bg-emerald-500/20 text-emerald-400 flex items-center justify-center text-xs">✓</span>'
                if r.get("blocked")
                else '<span class="w-5 h-5 rounded-full bg-red-500/20 text-red-400 flex items-center justify-center text-xs">✗</span>'
            )
            results_rows += f"""
            <div class="flex items-center gap-3 text-sm">
              {icon}
              <span class="font-mono text-gray-400">{r.get('path_id','')}</span>
              <span class="text-white">{r.get('category','')}</span>
            </div>"""

        hacker_section = f"""
        <div class="bg-gray-900 rounded-xl p-6 border border-gray-800 mb-8">
          <h2 class="text-lg font-semibold text-white mb-4">Hacker Pipeline Results</h2>
          <div class="grid grid-cols-2 sm:grid-cols-4 gap-4 mb-4">
            <div><div class="text-xs text-gray-500">Paths Discovered</div><div class="text-xl font-bold text-white">{recon.get('attack_paths',0)}</div></div>
            <div><div class="text-xs text-gray-500">Attacks Planned</div><div class="text-xl font-bold text-white">{len(hack.get('plans',[]))}</div></div>
            <div><div class="text-xs text-gray-500">Confirmed</div><div class="text-xl font-bold text-red-400">{len(confirmed)}</div></div>
            <div><div class="text-xs text-gray-500">Re-attack</div><div class="text-xl font-bold text-emerald-400">{len(blocked)}/{len(reattack)}</div></div>
          </div>
          <div class="mt-4 space-y-2">{results_rows}</div>
        </div>"""

    # --- Precompute card values ---
    scan_cls = 'text-amber-400' if findings else 'text-emerald-400'
    findings_plural = 's' if len(findings) != 1 else ''
    confirmed_list = [v for v in (hack or {}).get('validation', []) if v.get('validated')]
    confirmed_count = len(confirmed_list)
    hacker_cls = 'text-red-400' if confirmed_count else 'text-emerald-400'
    attacker_plural = 's' if confirmed_count != 1 else ''
    autofix_count = sum(1 for f in findings if f.get('id') in autofix_ids)

    # Verdict card
    verdict = (hack or {}).get('verification', {}).get('verdict', {})
    verdict_status = verdict.get('status', '')
    if verdict_status == 'SECURITY_VERIFIED':
        verdict_card = '<div class="text-emerald-400 font-bold text-xl">VERIFIED</div>'
    elif verdict_status == 'SECURITY_NOT_VERIFIED':
        verdict_card = '<div class="text-red-400 font-bold text-xl">NOT VERIFIED</div>'
    else:
        verdict_card = f'<div class="text-gray-500 font-bold text-xl">{verdict_status or "—"}</div>'

    severity_block = ''
    if severity_bars:
        severity_block = (
            '<div class="bg-gray-900 rounded-xl p-5 border border-gray-800 mb-8"><h2 class="text-lg '
            'font-semibold text-white mb-4">Severity '
            'Breakdown</h2><div class="space-y-3">'
            + severity_bars + '</div></div>'
        )

    findings_block = ''
    if findings_rows:
        findings_block = (
            '<div class="bg-gray-900 rounded-xl border '
            'border-gray-800 mb-8">'
            '<div class="p-5 border-b border-gray-800">'
            '<h2 class="text-lg font-semibold text-white">'
            'Static Analysis Findings</h2></div>'
            '<div class="overflow-x-auto">'
            '<table class="w-full text-sm">'
            '<thead><tr '
            'class="text-xs text-gray-500 uppercase '
            'tracking-wider border-b border-gray-800">'
            '<th class="px-4 py-3 text-left">Rule</th>'
            '<th class="px-4 py-3 text-left">Name</th>'
            '<th class="px-4 py-3 text-left">File</th>'
            '<th class="px-4 py-3 text-left">Line</th>'
            '<th class="px-4 py-3 text-left">Severity</th>'
            '<th class="px-4 py-3 text-left">Auto-fix</th>'
            '</tr></thead><tbody>'
            + findings_rows + '</tbody></table></div></div>'
        )

    body = f"""
    <div class="mb-6">
      <h1 class="text-2xl sm:text-3xl font-bold text-white mb-2">Security Dashboard</h1>
      <p class="text-gray-400 text-sm sm:text-base">Autonomous adversarial security scanning for Python codebases</p>
    </div>

    <div class="grid grid-cols-2 sm:grid-cols-3 lg:grid-cols-5 gap-3 sm:gap-4 mb-6">
      <div class="bg-gray-900 rounded-xl p-4 sm:p-5 border border-gray-800">
        <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Rules Active</div>
        <div class="text-2xl sm:text-3xl font-bold text-white">{len(RULES)}</div>
      </div>
      <div class="bg-gray-900 rounded-xl p-4 sm:p-5 border border-gray-800">
        <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Findings</div>
        <div class="text-2xl sm:text-3xl font-bold {scan_cls}">{len(findings)}</div>
        <div class="text-xs text-gray-500 mt-1">{len(findings)}{findings_plural}</div>
      </div>
      <div class="bg-gray-900 rounded-xl p-4 sm:p-5 border border-gray-800">
        <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Confirmed</div>
        <div class="text-2xl sm:text-3xl font-bold {hacker_cls}">{confirmed_count}</div>
        <div class="text-xs text-gray-500 mt-1">attack{attacker_plural}</div>
      </div>
      <div class="bg-gray-900 rounded-xl p-4 sm:p-5 border border-gray-800">
        <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Auto-Fixable</div>
        <div class="text-2xl sm:text-3xl font-bold text-brand-400">{autofix_count}</div>
        <div class="text-xs text-gray-500 mt-1">of {len(findings)}</div>
      </div>
      <div class="bg-gray-900 rounded-xl p-4 sm:p-5 border border-gray-800 col-span-2 sm:col-span-1">
        <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Verdict</div>
        {verdict_card}
      </div>
    </div>

    <!-- Start Assessment Button -->
    <div class="mb-6">
      <button onclick="startAssessment()" id="assess-btn"
        class="inline-flex items-center gap-2 bg-brand-600 hover:bg-brand-700 text-white font-semibold px-5 py-3 rounded-xl transition text-sm sm:text-base">
        <svg class="w-5 h-5" fill="none" viewBox="0 0 24 24" stroke="currentColor" stroke-width="2">
          <path stroke-linecap="round" stroke-linejoin="round" d="M14.752 11.168l-3.197-2.132A1 1 0 0010 9.87v4.263a1 1 0 001.555.832l3.197-2.132a1 1 0 000-1.664z"/>
          <path stroke-linecap="round" stroke-linejoin="round" d="M21 12a9 9 0 11-18 0 9 9 0 0118 0z"/>
        </svg>
        <span id="assess-btn-text">Start Security Assessment</span>
      </button>
      <span id="assess-status" class="text-sm text-gray-500 ml-3 hidden"></span>
    </div>

    {severity_block}
    {assessment_section}
    {hacker_section}
    {findings_block}

    <div class="grid grid-cols-1 sm:grid-cols-3 gap-4">
      <a href="/reports" class="bg-gray-900 hover:bg-gray-800 rounded-xl p-5 border border-gray-800 transition group">
        <div class="text-brand-400 font-semibold mb-1 group-hover:text-brand-300">Reports →</div>
        <div class="text-xs text-gray-500">Browse all scan and pipeline reports</div>
      </a>
      <a href="/pipeline" class="bg-gray-900 hover:bg-gray-800 rounded-xl p-5 border border-gray-800 transition group">
        <div class="text-brand-400 font-semibold mb-1 group-hover:text-brand-300">Assessment Details →</div>
        <div class="text-xs text-gray-500">Full finding-by-finding verification evidence</div>
      </a>
      <a href="/reports/raw" class="bg-gray-900 hover:bg-gray-800 rounded-xl p-5 border border-gray-800 transition group">
        <div class="text-brand-400 font-semibold mb-1 group-hover:text-brand-300">Raw JSON →</div>
        <div class="text-xs text-gray-500">Latest scan report as JSON</div>
      </a>
    </div>

    <script>
    async function startAssessment() {{
      const btn = document.getElementById('assess-btn');
      const btnText = document.getElementById('assess-btn-text');
      const status = document.getElementById('assess-status');
      btn.disabled = true;
      btnText.textContent = 'Running...';
      status.className = 'text-sm text-brand-400 ml-3';
      status.textContent = 'Starting security assessment pipeline...';
      status.classList.remove('hidden');
      try {{
        const resp = await fetch('/api/assess', {{method: 'POST', headers: {{'Content-Type': 'application/json'}}, body: JSON.stringify({{target: 'tests/hacker_target_web', approve: true}})}});
        const data = await resp.json();
        if (data.status === 'ok') {{
          status.className = 'text-sm text-emerald-400 ml-3';
          status.textContent = data.message;
          setTimeout(() => window.location.reload(), 1000);
        }} else {{
          status.className = 'text-sm text-red-400 ml-3';
          status.textContent = 'Error: ' + (data.message || 'Unknown error');
          btn.disabled = false;
          btnText.textContent = 'Start Security Assessment';
        }}
      }} catch(e) {{
        status.className = 'text-sm text-red-400 ml-3';
        status.textContent = 'Error: ' + e.message;
        btn.disabled = false;
        btnText.textContent = 'Start Security Assessment';
      }}
    }}
    </script>
    """

    return _page("Dashboard", body)


# ─── Reports ────────────────────────────────────────────────

@app.route("/reports")
def reports_list():
    reports = _list_reports()
    items = ""
    for r in reports:
        items += f"""
        <a href="/reports/{r['name']}" class="block bg-gray-900 hover:bg-gray-800 rounded-xl p-5 border border-gray-800 transition">
          <div class="flex items-center justify-between">
            <div>
              <div class="font-mono text-brand-400 text-sm mb-1">{r['name']}</div>
              <div class="text-white font-medium">{r['title']}</div>
            </div>
            <div class="text-right text-xs text-gray-500">{r['size']}</div>
          </div>
        </a>"""

    if not items:
        items = '<div class="bg-gray-900 rounded-xl p-8 border border-gray-800 text-center text-gray-500">No reports yet. Run a scan first.</div>'

    body = f"""
    <div class="mb-8">
      <h1 class="text-2xl sm:text-3xl font-bold text-white mb-2">Security Reports</h1>
      <p class="text-gray-400">Available scan and pipeline reports</p>
    </div>
    <div class="space-y-4">{items}</div>
    """
    return _page("Reports", body)


@app.route("/reports/<name>")
def report_detail(name):
    if name == "raw":
        scan = _load_json("scan_report.json")
        return jsonify(scan or {"error": "No scan report found"})

    path = PROJECT_ROOT / "reports" / name
    if not path.exists():
        return "Report not found", 404

    with open(path) as f:
        content = f.read()

    try:
        return jsonify(json.loads(content))
    except json.JSONDecodeError:
        return content, 200, {"Content-Type": "text/plain"}


@app.route("/reports/raw")
def report_raw():
    scan = _load_json("scan_report.json")
    return jsonify(scan or {"error": "No scan report found"})


# ─── Assessment Detail (Pipeline page) ─────────────────────

@app.route("/pipeline")
def pipeline():
    hack = _load_json("orchestrator_report.json")
    scan = _load_json("scan_report.json")

    if not hack:
        body = """
        <div class="mb-8">
          <h1 class="text-2xl sm:text-3xl font-bold text-white mb-2">Security Assessment</h1>
          <p class="text-gray-400">No assessment has been run yet.</p>
        </div>
        <div class="bg-gray-900 rounded-xl p-8 border border-gray-800 text-center">
          <p class="text-gray-500 mb-4">Go to the Dashboard and click <strong class="text-brand-400">Start Security Assessment</strong> to begin.</p>
          <a href="/" class="text-brand-400 hover:text-brand-300 text-sm font-medium">← Back to Dashboard</a>
        </div>"""
        return _page("Assessment", body)

    recon = hack.get("recon", {})
    plans = hack.get("plans", [])
    validation = hack.get("validation", [])
    confirmed = [v for v in validation if v.get("validated")]
    rem = hack.get("remediation", {})
    rem_result = rem.get("result", {})
    applied = [r for r in rem_result.get("results", []) if r.get("status") == "APPLIED"]
    requires_review = rem.get("requires_review", [])
    hv = hack.get("hacker_verification", {})
    reattack = hv.get("results", [])
    blocked = [r for r in reattack if r.get("blocked")]
    verification = hack.get("verification", {})
    verdict = verification.get("verdict", {})
    static_scan = verification.get("static_scan", {})
    tests = verification.get("tests", {})
    status = hack.get("status", "UNKNOWN")

    verdict_color = "emerald" if status == "SECURITY_VERIFIED" else "red"
    verdict_bg = f"bg-{verdict_color}-500/10 text-{verdict_color}-400 border-{verdict_color}-500/30"

    # --- Build validation evidence per path ---
    reattack_map = {r.get("path_id"): r for r in reattack}

    path_cards = ""
    for v in validation:
        pid = v.get("path_id", "")
        cat = v.get("category", "")
        validated = v.get("validated", False)
        validator = v.get("validator", "")
        payload = v.get("payload", "")
        evidence = v.get("evidence", "")

        ra = reattack_map.get(pid, {})
        ra_blocked = ra.get("blocked", False)
        ra_status = ra.get("status", "")
        ra_evidence = ra.get("evidence", "")

        val_badge = _badge("CONFIRMED" if validated else "NOT CONFIRMED", "green" if validated else "gray")
        ra_badge = _badge("BLOCKED" if ra_blocked else "STILL WORKS", "green" if ra_blocked else "red") if ra else _badge("NOT TESTED", "gray")

        # Find matching remediation
        rem_status = "NOT APPLIED"
        rem_file = ""
        for ar in applied:
            if cat in str(ar.get("findings", [])):
                rem_status = "APPLIED"
                rem_file = ar.get("file", "")
                break

        rem_badge = _badge(rem_status, "green" if rem_status == "APPLIED" else "gray")

        path_cards += f"""
        <div class="bg-gray-900 rounded-xl border border-gray-800 mb-4">
          <div class="p-4 border-b border-gray-800 flex items-center justify-between flex-wrap gap-2">
            <div class="flex items-center gap-3 flex-wrap">
              <span class="font-mono text-brand-400 font-medium">{pid}</span>
              <span class="text-white font-medium">{cat}</span>
              {val_badge}
              {rem_badge}
              {ra_badge}
            </div>
          </div>
          <div class="p-4 text-sm space-y-3">
            <div class="grid grid-cols-1 sm:grid-cols-2 gap-3">
              <div>
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Attack Payload</div>
                <div class="font-mono text-xs bg-gray-800 rounded p-2 text-gray-300 break-all">{payload}</div>
              </div>
              <div>
                <div class="text-xs text-gray-500 uppercase tracking-wider mb-1">Validation Evidence</div>
                <div class="text-gray-400 text-xs">{evidence[:200] if evidence else '—'}</div>
              </div>
            </div>
            {"<div><div class='text-xs text-gray-500 uppercase tracking-wider mb-1'>Re-attack Evidence</div><div class='text-gray-400 text-xs'>" + (ra_evidence[:200] if ra_evidence else '—') + "</div></div>" if ra else ""}
          </div>
        </div>"""

    # --- Build verification steps ---
    steps = [
        ("Discovery", "DISCOVER", True, [
            f"{recon.get('files_analyzed', 0)} files analyzed",
            f"{recon.get('attack_surfaces', 0)} attack surfaces",
            f"{recon.get('attack_paths', 0)} attack paths discovered",
        ]),
        ("Validation", "VALIDATE", bool(confirmed), [
            f"{len(plans)} attack paths planned",
            f"{len(confirmed)}/{len(plans)} attacks confirmed",
        ]),
        ("Remediation", "REMEDIATE", bool(applied), [
            f"{rem.get('available', 0)} auto-fixable",
            f"{len(requires_review)} requiring manual review",
            f"{len(applied)} fixes applied",
        ]),
        ("Rescan", "RESCAN", "passed" in static_scan, [
            "Static rescan: " + ("PASS" if static_scan.get("passed") else "FAIL"),
            f"{len(static_scan.get('remaining_original_findings', []))} original findings remain",
        ]),
        ("Tests", "TEST", "passed" in tests, [
            "Tests: " + ("PASS" if tests.get("passed") else "FAIL"),
        ]),
        ("Re-attack", "RE-ATTACK", bool(reattack), [
            f"{len(blocked)}/{len(reattack)} attacks blocked",
        ]),
    ]

    steps_html = ""
    for label, keyword, done, details in steps:
        detail_items = "".join(f'<li class="text-xs text-gray-400">• {d}</li>' for d in details)
        steps_html += f"""
        <div class="flex items-start gap-3">
          {_step_icon(done)}
          <div class="flex-1">
            <div class="font-medium text-white text-sm">{label}</div>
            <ul class="mt-1 space-y-0.5">{detail_items}</ul>
          </div>
        </div>"""

    # --- Final verdict card ---
    verdict_items = [
        ("Static scan", verdict.get("static_scan_passed")),
        ("Tests", verdict.get("tests_passed")),
        ("Re-attack", verdict.get("hacker_verification_passed")),
    ]
    verdict_details = ""
    for label, passed in verdict_items:
        icon = "✓" if passed else "✗"
        color = "text-emerald-400" if passed else "text-red-400"
        verdict_details += f'<div class="flex items-center gap-2 text-sm"><span class="{color}">{icon}</span><span class="text-gray-400">{label}</span></div>'

    body = f"""
    <div class="mb-6 flex items-center justify-between flex-wrap gap-3">
      <div>
        <h1 class="text-2xl sm:text-3xl font-bold text-white mb-1">Security Assessment</h1>
        <p class="text-gray-400 text-sm">Full finding-by-finding verification evidence</p>
      </div>
      <div class="flex items-center gap-3">
        <span class="text-sm px-4 py-1.5 rounded-full font-medium {verdict_bg}">{status}</span>
        <a href="/" class="text-sm text-gray-500 hover:text-white transition">← Dashboard</a>
      </div>
    </div>

    <!-- Verification Flow -->
    <div class="bg-gray-900 rounded-xl border border-gray-800 p-5 mb-6">
      <h2 class="text-lg font-semibold text-white mb-4">Verification Flow</h2>
      <div class="space-y-4">{steps_html}</div>
      <div class="mt-6 p-4 bg-gray-800/50 rounded-lg border border-gray-700">
        <div class="text-sm font-medium text-white mb-2">Final Verdict: <span class="{verdict_bg} px-2 py-0.5 rounded text-xs font-medium">{status}</span></div>
        <div class="space-y-1">{verdict_details}</div>
      </div>
    </div>

    <!-- Per-Finding Evidence -->
    <div class="mb-6">
      <h2 class="text-lg font-semibold text-white mb-4">Finding Evidence</h2>
      {path_cards}
    </div>

    <!-- Remediation Details -->
    {"<div class='bg-gray-900 rounded-xl border border-gray-800 p-5 mb-6'><h2 class='text-lg font-semibold text-white mb-4'>Applied Fixes</h2><div class='space-y-3'>" + "".join(f"<div class='flex items-center gap-3 text-sm'><span class='text-emerald-400'>✓</span><span class='font-mono text-gray-400'>{ar.get('file','')}</span><span class='text-gray-500'>→</span><span class='text-white'>{', '.join(ar.get('findings',[]))}</span></div>" for ar in applied) + "</div></div>" if applied else ""}
    """

    return _page("Assessment", body)


# ─── API: Trigger Scan ─────────────────────────────────────

@app.route("/api/scan", methods=["POST"])
def api_scan():
    target = request.json.get("target", ".") if request.is_json else "."
    try:
        subprocess.run(
            [sys.executable, "main.py", "scan", target, "--json"],
            capture_output=True,
            text=True,
            timeout=120,
            cwd=str(PROJECT_ROOT),
        )
        scan = _load_json("scan_report.json")
        return jsonify({"status": "ok", "findings": len(scan.get("findings", [])) if scan else 0})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


# ─── API: Trigger Full Assessment ──────────────────────────

@app.route("/api/assess", methods=["POST"])
def api_assess():
    """Run the full orchestrator pipeline: discover → validate →
    remediate → rescan → test → re-attack → verdict.

    POST body: {"target": "tests/hacker_target_web", "approve": true}
    """
    data = request.json if request.is_json else {}
    target = data.get("target", "tests/hacker_target_web")
    approve = data.get("approve", True)

    try:
        result = subprocess.run(
            [
                sys.executable, "main.py", "hack",
                target,
            ] + (["--approve"] if approve else []),
            capture_output=True,
            text=True,
            timeout=180,
            cwd=str(PROJECT_ROOT),
        )

        # The orchestrator writes its report to reports/orchestrator_report.json
        hack_report = _load_json("orchestrator_report.json")
        if not hack_report:
            return jsonify({
                "status": "error",
                "message": "Pipeline did not produce a report.",
                "stdout": result.stdout[-500:] if result.stdout else "",
                "stderr": result.stderr[-500:] if result.stderr else "",
            }), 500

        status = hack_report.get("status", "UNKNOWN")
        confirmed = hack_report.get("confirmed_attacks", 0)
        verification = hack_report.get("verification", {})
        verdict = verification.get("verdict", {})

        msg = f"Assessment complete: {status}"
        if status == "SECURITY_VERIFIED":
            msg = f"Security verified — {confirmed} attacks confirmed and blocked"
        elif status == "SECURITY_NOT_VERIFIED":
            msg = f"Assessment complete — {confirmed} attacks confirmed, some still exploitable"
        else:
            msg = f"Assessment complete — {status}"

        return jsonify({
            "status": "ok",
            "message": msg,
            "assessment_status": status,
            "confirmed_attacks": confirmed,
            "verdict": verdict.get("status", ""),
        })

    except subprocess.TimeoutExpired:
        return jsonify({
            "status": "error",
            "message": "Assessment timed out (>180s). Target may be too complex.",
        }), 500
    except Exception as e:
        return jsonify({
            "status": "error",
            "message": str(e),
        }), 500


if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port, debug=False)
