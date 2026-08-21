"""
Interactive visual report and diff visualizer for AgentScope.
Generates standalone, self-contained HTML reports with zero external dependencies.
"""

from __future__ import annotations
import html
from typing import Optional, Dict, Any, List
from .models import CapabilityFingerprint, CapabilityDelta, RiskLevel


CSS_STYLES = """
:root {
  --bg-primary: #0f172a;
  --bg-secondary: #1e293b;
  --bg-card: #182234;
  --border-color: #334155;
  --text-primary: #f8fafc;
  --text-secondary: #94a3b8;
  --accent-cyan: #38bdf8;
  --accent-green: #22c55e;
  --accent-yellow: #eab308;
  --accent-red: #ef4444;
  --font-mono: ui-monospace, SFMono-Regular, Menlo, Monaco, Consolas, monospace;
  --font-sans: -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
}

* { box-sizing: border-box; margin: 0; padding: 0; }
body {
  background-color: var(--bg-primary);
  color: var(--text-primary);
  font-family: var(--font-sans);
  line-height: 1.5;
  padding: 2rem;
}
.container { max-width: 1100px; margin: 0 auto; }
header {
  border-bottom: 1px solid var(--border-color);
  padding-bottom: 1.5rem;
  margin-bottom: 2rem;
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.title-group h1 { font-size: 1.75rem; font-weight: 700; color: var(--text-primary); }
.title-group p { color: var(--text-secondary); font-size: 0.9rem; margin-top: 0.25rem; }
.badge {
  display: inline-block;
  padding: 0.35rem 0.75rem;
  border-radius: 9999px;
  font-size: 0.8rem;
  font-weight: 600;
  text-transform: uppercase;
  letter-spacing: 0.05em;
}
.badge-low { background: rgba(34, 197, 94, 0.15); color: var(--accent-green); border: 1px solid rgba(34, 197, 94, 0.3); }
.badge-medium { background: rgba(234, 179, 8, 0.15); color: var(--accent-yellow); border: 1px solid rgba(234, 179, 8, 0.3); }
.badge-high, .badge-critical { background: rgba(239, 68, 68, 0.15); color: var(--accent-red); border: 1px solid rgba(239, 68, 68, 0.3); }

.stats-grid {
  display: grid;
  grid-template-columns: repeat(auto-fit, minmax(180px, 1fr));
  gap: 1rem;
  margin-bottom: 2rem;
}
.stat-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  padding: 1.25rem;
}
.stat-card .label { font-size: 0.8rem; color: var(--text-secondary); text-transform: uppercase; letter-spacing: 0.05em; }
.stat-card .value { font-size: 1.75rem; font-weight: 700; color: var(--accent-cyan); margin-top: 0.25rem; }

.section-card {
  background: var(--bg-secondary);
  border: 1px solid var(--border-color);
  border-radius: 8px;
  margin-bottom: 1.5rem;
  overflow: hidden;
}
.section-header {
  background: var(--bg-card);
  padding: 0.75rem 1.25rem;
  font-weight: 600;
  font-size: 0.95rem;
  border-bottom: 1px solid var(--border-color);
  display: flex;
  justify-content: space-between;
  align-items: center;
}
.item-list { list-style: none; padding: 0.5rem 0; font-family: var(--font-mono); font-size: 0.85rem; }
.item-list li {
  padding: 0.4rem 1.25rem;
  border-bottom: 1px solid rgba(51, 65, 85, 0.4);
  display: flex;
  align-items: center;
}
.item-list li:last-child { border-bottom: none; }
.item-added { color: var(--accent-green); background: rgba(34, 197, 94, 0.05); }
.item-removed { color: var(--text-secondary); text-decoration: line-through; opacity: 0.6; }
.item-warning { color: var(--accent-red); font-weight: 600; }
.icon-warn { color: var(--accent-yellow); margin-left: 0.5rem; }
.empty-msg { padding: 1rem 1.25rem; color: var(--text-secondary); font-style: italic; font-size: 0.85rem; }

.diff-reasons {
  background: rgba(239, 68, 68, 0.05);
  border: 1px solid rgba(239, 68, 68, 0.2);
  border-radius: 8px;
  padding: 1.25rem;
  margin-bottom: 2rem;
}
.diff-reasons h3 { color: var(--accent-red); font-size: 1rem; margin-bottom: 0.5rem; }
.diff-reasons ul { margin-left: 1.5rem; color: var(--text-primary); font-size: 0.9rem; }
"""


def render_fingerprint_html(fp: CapabilityFingerprint, title: str = "AgentScope Authority Report") -> str:
    """
    Renders a single CapabilityFingerprint into a standalone HTML document.
    """
    caps = fp.capabilities
    meta = fp.metadata
    
    agent_name = html.escape(meta.agent if meta else "unknown")
    cmd_str = html.escape(" ".join(meta.command) if meta else "N/A")
    duration = f"{meta.duration_ms}ms" if meta else "N/A"
    exit_code = str(meta.exit_code) if meta else "N/A"
    timestamp = html.escape(meta.timestamp if meta else "")

    def render_items(items: List[str], warn_secrets: bool = False) -> str:
        if not items:
            return '<div class="empty-msg">None recorded</div>'
        html_items = []
        for it in items:
            escaped = html.escape(it)
            warn_badge = '<span class="icon-warn">⚠</span>' if (warn_secrets or "⚠" in it or "env:" in it) else ""
            html_items.append(f'<li><span>{escaped}</span>{warn_badge}</li>')
        return f'<ul class="item-list">{"".join(html_items)}</ul>'

    body_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <style>{CSS_STYLES}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1>{html.escape(title)}</h1>
        <p>Agent: <strong>{agent_name}</strong> | Command: <code>{cmd_str}</code> | {timestamp}</p>
      </div>
      <div>
        <span class="badge badge-low">Exit: {exit_code}</span>
      </div>
    </header>

    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Files Read</div>
        <div class="value">{len(caps.filesystem.read)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Files Written</div>
        <div class="value">{len(caps.filesystem.write)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Commands</div>
        <div class="value">{len(caps.commands)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Network Endpoints</div>
        <div class="value">{len(caps.network)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Secrets Accessed</div>
        <div class="value" style="color: {'var(--accent-red)' if caps.secrets else 'var(--accent-green)'}">{len(caps.secrets)}</div>
      </div>
    </div>

    {f'''
    <div class="section-card">
      <div class="section-header">
        <span>Secrets & Credentials Accessed</span>
        <span class="badge badge-critical">{len(caps.secrets)}</span>
      </div>
      {render_items(caps.secrets, warn_secrets=True)}
    </div>
    ''' if caps.secrets else ''}

    <div class="section-card">
      <div class="section-header">
        <span>Files Written</span>
        <span class="badge badge-low">{len(caps.filesystem.write)}</span>
      </div>
      {render_items(caps.filesystem.write)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Files Read</span>
        <span class="badge badge-low">{len(caps.filesystem.read)}</span>
      </div>
      {render_items(caps.filesystem.read)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Commands Executed</span>
        <span class="badge badge-low">{len(caps.commands)}</span>
      </div>
      {render_items(caps.commands)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Outbound Network Sockets</span>
        <span class="badge badge-low">{len(caps.network)}</span>
      </div>
      {render_items(caps.network)}
    </div>
  </div>
</body>
</html>
"""
    return body_html


def render_diff_html(
    delta: CapabilityDelta,
    title: str = "AgentScope Authority Diff"
) -> str:
    """
    Renders a CapabilityDelta into an interactive visual diff HTML report.
    """
    risk_class = f"badge-{delta.risk_level.value.lower()}"

    def render_diff_section(added: List[str], removed: List[str], warn: bool = False) -> str:
        if not added and not removed:
            return '<div class="empty-msg">No changes</div>'
        items = []
        for a in added:
            escaped = html.escape(a)
            warn_icon = '<span class="icon-warn">⚠</span>' if warn else ''
            items.append(f'<li class="item-added">+ {escaped} {warn_icon}</li>')
        for r in removed:
            escaped = html.escape(r)
            items.append(f'<li class="item-removed">- {escaped}</li>')
        return f'<ul class="item-list">{"".join(items)}</ul>'

    reasons_html = ""
    if delta.risk_reasons:
        reason_items = "".join(f"<li>{html.escape(r)}</li>" for r in delta.risk_reasons)
        reasons_html = f"""
        <div class="diff-reasons">
          <h3>Authority Escalation Triggers</h3>
          <ul>{reason_items}</ul>
        </div>
        """

    body_html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>{html.escape(title)}</title>
  <style>{CSS_STYLES}</style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1>{html.escape(title)}</h1>
        <p>Authority Delta Analysis between Baseline and Candidate</p>
      </div>
      <div>
        <span class="badge {risk_class}">Risk: {delta.risk_level.value}</span>
      </div>
    </header>

    {reasons_html}

    <div class="stats-grid">
      <div class="stat-card">
        <div class="label">Added Secrets</div>
        <div class="value" style="color: {'var(--accent-red)' if delta.added_secrets else 'var(--accent-green)'}">+{len(delta.added_secrets)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Added Writes</div>
        <div class="value">+{len(delta.added_files_written)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Added Commands</div>
        <div class="value">+{len(delta.added_commands)}</div>
      </div>
      <div class="stat-card">
        <div class="label">Added Network</div>
        <div class="value">+{len(delta.added_network)}</div>
      </div>
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Secrets & Credentials Delta</span>
        <span class="badge {risk_class}">+{len(delta.added_secrets)}</span>
      </div>
      {render_diff_section(delta.added_secrets, delta.removed_secrets, warn=True)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Files Written Delta</span>
      </div>
      {render_diff_section(delta.added_files_written, delta.removed_files_written)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Files Read Delta</span>
      </div>
      {render_diff_section(delta.added_files_read, delta.removed_files_read)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Commands Delta</span>
      </div>
      {render_diff_section(delta.added_commands, delta.removed_commands)}
    </div>

    <div class="section-card">
      <div class="section-header">
        <span>Network Endpoints Delta</span>
      </div>
      {render_diff_section(delta.added_network, delta.removed_network)}
    </div>
  </div>
</body>
</html>
"""
    return body_html
