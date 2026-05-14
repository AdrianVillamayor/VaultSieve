from __future__ import annotations

from html import escape

from vaultsieve.analyzers.duplicates import duplicate_cleanup_plan
from vaultsieve.analyzers.domains import extract_domain
from vaultsieve.models import AuditReport, Finding, SEVERITY_ORDER

SEVERITY_LABELS = ("critical", "high", "medium", "low", "obsolete")


def render_html_report(
    report: AuditReport,
    *,
    favicon_href: str = "vaultsieve-icon.svg",
    icon_href: str = "vaultsieve-icon.svg",
) -> str:
    findings = sorted(
        report.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
    dashboard = _dashboard_metrics(report)
    generated_summary = _render_summary(report, dashboard)
    score_panel = _render_score_panel(report, dashboard)
    action_plan = _render_action_plan(report, dashboard)
    inventory = _render_inventory(dashboard)
    filters = _render_filters(findings)
    finding_cards = _render_finding_cards(report, findings)
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>VaultSieve Audit Report</title>
  <link rel="icon" href="{escape(favicon_href, quote=True)}" type="image/svg+xml">
  <style>{_render_styles()}</style>
</head>
<body>
  <main class="shell">
    <header class="hero">
      <div>
        <div class="brand-lockup" aria-label="VaultSieve">
          <img class="brand-icon" src="{escape(icon_href, quote=True)}" alt="" aria-hidden="true">
          <span class="brand-name">VaultSieve</span>
        </div>
        <p class="eyebrow">Local report</p>
        <h2>Password vault audit</h2>
        <p class="muted">Local report generated from an exported vault. Full plaintext passwords are not included.</p>
      </div>
      <div class="meta-card">
        <span>Input</span>
        <strong>{escape(str(report.input_path))}</strong>
        <span>Format</span>
        <strong>{escape(report.input_format)}</strong>
      </div>
    </header>

    {inventory}

    {score_panel}

    {generated_summary}

    {filters}

    <section class="toolbar-result">
      <span id="visible-count">{len(findings)}</span> visible findings
    </section>

    <section class="findings" id="findings">
      {finding_cards}
    </section>

    {action_plan}

    <section class="notice">
      <strong>Safety note:</strong> This report contains account names, usernames, URLs, source indexes, and findings. Treat it as sensitive even though plaintext passwords are excluded.
      {_render_attribution(report)}
    </section>
  </main>
  <script>{_render_script()}</script>
</body>
</html>
"""


def _dashboard_metrics(report: AuditReport) -> dict[str, int]:
    category_counts: dict[str, int] = {}
    for finding in report.findings:
        category_counts[finding.category] = category_counts.get(finding.category, 0) + 1

    cleanup_plan = duplicate_cleanup_plan(report.credentials)
    safe_duplicate_removals = sum(len(decision.remove_ids) for decision in cleanup_plan)
    ambiguous_duplicate_groups = sum(1 for decision in cleanup_plan if not decision.remove_ids)
    web_entries = sum(1 for credential in report.credentials if any(extract_domain(url) for url in credential.urls))
    app_entries = sum(
        1
        for credential in report.credentials
        if credential.urls and not any(extract_domain(url) for url in credential.urls)
    )
    passkeys = sum(1 for credential in report.credentials if credential.has_passkey)
    ssh_keys = sum(1 for credential in report.credentials if credential.is_ssh_key)
    highest_risk = category_counts.get("breached", 0) + category_counts.get("empty", 0)
    needs_review = (
        category_counts.get("reuse", 0)
        + category_counts.get("domain_missing", 0)
        + category_counts.get("two_factor_not_stored", 0)
        + category_counts.get("service_known_breach", 0)
        + ambiguous_duplicate_groups
    )
    severity_counts = report.summary_by_severity
    penalty = (
        min(45, severity_counts["critical"] * 10)
        + min(25, severity_counts["high"] * 5)
        + min(15, severity_counts["medium"] * 2)
        + min(8, severity_counts["low"])
        + min(7, severity_counts["obsolete"])
    )
    health_score = 100 if not report.findings else max(5, 100 - penalty)
    return {
        "health_score": health_score,
        "safe_duplicate_removals": safe_duplicate_removals,
        "ambiguous_duplicate_groups": ambiguous_duplicate_groups,
        "highest_risk": highest_risk,
        "needs_review": needs_review,
        "web_entries": web_entries,
        "app_entries": app_entries,
        "passkeys": passkeys,
        "ssh_keys": ssh_keys,
        "breached": category_counts.get("breached", 0),
        "empty": category_counts.get("empty", 0),
        "reuse": category_counts.get("reuse", 0),
        "domain_missing": category_counts.get("domain_missing", 0),
        "two_factor_not_stored": category_counts.get("two_factor_not_stored", 0),
        "service_known_breach": category_counts.get("service_known_breach", 0),
        "weak": category_counts.get("weak", 0),
    }


def _render_summary(report: AuditReport, dashboard: dict[str, int]) -> str:
    cards = [
        _summary_card("Health score", str(dashboard["health_score"]), "0-100 action score"),
        _summary_card("Safe cleanup", str(dashboard["safe_duplicate_removals"]), "Low-risk duplicate removals"),
        _summary_card("Needs review", str(dashboard["needs_review"]), "Manual decisions"),
        _summary_card("Highest risk", str(dashboard["highest_risk"]), "Breached or empty passwords", "critical"),
        _summary_card("Credentials", str(len(report.credentials)), "Entries imported"),
        _summary_card("Findings", str(len(report.findings)), "Total issues detected"),
    ]
    return f"<section class=\"summary-grid\">{''.join(cards)}</section>"


def _render_score_panel(report: AuditReport, dashboard: dict[str, int]) -> str:
    chart = _render_severity_chart(report)
    return f"""
    <section class="score-panel">
      <div class="score-orb" style="--score: {dashboard['health_score']};">
        <strong>{dashboard['health_score']}</strong>
        <span>health score</span>
      </div>
      <div class="score-copy">
        <p class="section-kicker">Summary chart</p>
        <h2>Risk at a glance</h2>
        <p>The health score starts at 100 and subtracts capped penalties by severity: critical findings have the strongest impact, then high, medium, low, and obsolete. Penalties are capped so large vaults do not collapse to 0 just because many similar findings repeat.</p>
        {chart}
      </div>
    </section>
    """


def _render_severity_chart(report: AuditReport) -> str:
    max_count = max(report.summary_by_severity.values(), default=0) or 1
    rows = []
    for severity in SEVERITY_LABELS:
        count = report.summary_by_severity[severity]
        width = max(4, round((count / max_count) * 100)) if count else 0
        rows.append(
            f"""
            <div class="chart-row severity-{escape(severity)}">
              <span>{escape(severity.title())}</span>
              <div class="chart-track"><i style="width: {width}%"></i></div>
              <strong>{count}</strong>
            </div>
            """
        )
    return f"<div class=\"severity-chart\">{''.join(rows)}</div>"


def _summary_card(title: str, value: str, subtitle: str, severity: str | None = None) -> str:
    severity_class = f" severity-{severity}" if severity else ""
    return (
        f"<article class=\"summary-card{severity_class}\">"
        f"<span>{escape(title)}</span>"
        f"<strong>{escape(value)}</strong>"
        f"<small>{escape(subtitle)}</small>"
        "</article>"
    )


def _render_action_plan(report: AuditReport, dashboard: dict[str, int]) -> str:
    actions: list[str] = []
    if dashboard["breached"]:
        actions.append(f"Change {dashboard['breached']} breached password entries first.")
    if dashboard["empty"]:
        actions.append(f"Fix {dashboard['empty']} empty password entries.")
    if dashboard["reuse"]:
        actions.append(f"Review {dashboard['reuse']} password reuse groups and rotate reused passwords.")
    if dashboard["safe_duplicate_removals"]:
        actions.append(f"Create a clean output to remove {dashboard['safe_duplicate_removals']} safe exact duplicates.")
    if dashboard["domain_missing"]:
        actions.append(f"Review {dashboard['domain_missing']} missing-domain groups before deleting obsolete entries.")
    if dashboard["two_factor_not_stored"]:
        actions.append(f"Confirm 2FA on {dashboard['two_factor_not_stored']} TOTP-capable services not stored in this vault.")
    if dashboard["service_known_breach"]:
        actions.append(f"Review {dashboard['service_known_breach']} services with public breach history.")
    if dashboard["weak"]:
        actions.append(f"Replace weak passwords after critical and reuse issues are handled.")
    if not actions:
        actions.append("No immediate action required from the current checks.")
    items = "".join(f"<li>{escape(action)}</li>" for action in actions)
    return f"""
    <section class="action-panel">
      <div>
        <p class="section-kicker">Recommended next steps</p>
        <h2>What to do first</h2>
      </div>
      <ol>{items}</ol>
    </section>
    """


def _render_inventory(dashboard: dict[str, int]) -> str:
    items = [
        ("Web entries", dashboard["web_entries"], "Checked for resolvable domains when enabled"),
        ("App entries", dashboard["app_entries"], "Skipped from web domain checks"),
        ("Passkeys", dashboard["passkeys"], "Skipped from empty-password warnings"),
        ("SSH keys", dashboard["ssh_keys"], "Skipped from web password/domain checks"),
        ("Ambiguous duplicates", dashboard["ambiguous_duplicate_groups"], "Kept because no clear keeper exists"),
    ]
    cards = "".join(
        _summary_card(title, str(value), subtitle)
        for title, value, subtitle in items
    )
    return f"""
    <section class="inventory-panel">
      <div>
        <p class="section-kicker">Inventory</p>
        <h2>What VaultSieve understood</h2>
      </div>
      <div class="inventory-grid">{cards}</div>
    </section>
    """


def _render_attribution(report: AuditReport) -> str:
    parts: list[str] = []
    if any(finding.category == "two_factor_not_stored" for finding in report.findings):
        parts.append("Data sourced from <a href=\"https://2fa.directory/\">2FA Directory</a> by <a href=\"https://github.com/2factorauth/\">2factorauth</a>.")
    if any(finding.category == "service_known_breach" for finding in report.findings):
        parts.append("Breach catalogue data sourced from <a href=\"https://haveibeenpwned.com/\">Have I Been Pwned</a>.")
    return " " + " ".join(parts) if parts else ""


def _render_filters(findings: list[Finding]) -> str:
    categories = sorted({finding.category for finding in findings})
    severity_options = ''.join(
        f'<option value="{escape(severity)}">{escape(severity.title())}</option>'
        for severity in SEVERITY_LABELS
    )
    category_options = ''.join(
        f'<option value="{escape(category)}">{escape(category.replace("_", " ").title())}</option>'
        for category in categories
    )
    return f"""
    <section class="filters" aria-label="Report filters">
      <label>
        Search
        <input id="search" type="search" placeholder="Search names, usernames, URLs, recommendations...">
      </label>
      <label>
        Severity
        <select id="severity-filter">
          <option value="all">All severities</option>
          {severity_options}
        </select>
      </label>
      <label>
        Category
        <select id="category-filter">
          <option value="all">All categories</option>
          {category_options}
        </select>
      </label>
    </section>
    """


def _render_finding_cards(report: AuditReport, findings: list[Finding]) -> str:
    if not findings:
        return "<article class=\"empty-state\">No findings detected.</article>"

    credential_map = report.credential_map()
    cards: list[str] = []
    for index, finding in enumerate(findings, start=1):
        credential_items: list[str] = []
        search_parts = [finding.severity, finding.category,
                        finding.explanation, finding.recommendation]
        for credential_id in finding.credential_ids:
            credential = credential_map.get(credential_id)
            if credential is None:
                continue
            urls = ", ".join(credential.urls) if credential.urls else "No URL"
            search_parts.extend(
                [credential.id, credential.name, credential.username, urls])
            credential_items.append(
                "<li>"
                f"<strong>{escape(credential.name or '(unnamed)')}</strong>"
                f"<span>{escape(credential.username or '(no username)')}</span>"
                f"<code>{escape(credential.id)}</code>"
                f"<small>{escape(urls)}</small>"
                "</li>"
            )

        search_text = escape(" ".join(search_parts).lower(), quote=True)
        cards.append(
            f"""
            <article class="finding-card severity-{escape(finding.severity)}" data-severity="{escape(finding.severity)}" data-category="{escape(finding.category)}" data-search="{search_text}">
              <div class="finding-header">
                <span class="badge">{escape(finding.severity)}</span>
                <span class="category">{escape(finding.category.replace('_', ' '))}</span>
                <strong>{escape(finding.explanation)}</strong>
              </div>
              <div class="finding-body">
                <div>
                  <h3>Recommendation</h3>
                  <p>{escape(finding.recommendation)}</p>
                </div>
                <div>
                  <h3>Affected credentials</h3>
                  <ul class="credential-list">{''.join(credential_items)}</ul>
                </div>
              </div>
            </article>
            """
        )
    return "".join(cards)


def _render_styles() -> str:
    return """
:root {
  color-scheme: light;
  --page: #fafafa;
  --panel: #ffffff;
  --panel-soft: #f6f7f7;
  --ink: #111827;
  --muted: #667085;
  --subtle: #98a2b3;
  --line: #dfe4e8;
  --line-strong: #cbd5dc;
  --accent: #0f766e;
  --accent-soft: #e6f5f2;
  --critical: #dc2626;
  --critical-soft: #fee2e2;
  --high: #ea580c;
  --high-soft: #ffedd5;
  --medium: #ca8a04;
  --medium-soft: #fef3c7;
  --low: #2563eb;
  --low-soft: #dbeafe;
  --obsolete: #6b7280;
  --obsolete-soft: #f3f4f6;
  --dot: rgba(15, 23, 42, 0.14);
  --shadow: 0 18px 45px rgba(15, 23, 42, 0.08);
  --radius: 16px;
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle, var(--dot) 1px, transparent 1.4px),
    linear-gradient(180deg, rgba(240, 253, 250, 0.86), rgba(250, 250, 250, 0.9) 34rem),
    var(--page);
  background-size: 24px 24px, auto, auto;
  color: var(--ink);
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
}
.shell { width: min(1180px, calc(100% - 2rem)); margin: 0 auto; padding: 2rem 0 2.5rem; }
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(260px, 340px);
  gap: 1.25rem;
  align-items: end;
  border: 1px solid var(--line);
  border-radius: calc(var(--radius) + 6px);
  background: rgba(255, 255, 255, 0.88);
  box-shadow: var(--shadow);
  padding: 1.35rem;
  margin-bottom: 1rem;
  backdrop-filter: blur(8px);
}
.brand-lockup { display: flex; align-items: center; gap: 0.7rem; margin-bottom: 1.25rem; }
.brand-icon { width: 2.55rem; height: 2.55rem; object-fit: contain; border-radius: 0.7rem; background: var(--accent-soft); border: 1px solid rgba(15, 118, 110, 0.22); padding: 0.32rem; }
.brand-name { font-size: 1.05rem; font-weight: 700; letter-spacing: -0.02em; color: var(--ink); }
.hero h1 { font-size: clamp(2rem, 5vw, 4.15rem); line-height: 0.96; margin: 0; letter-spacing: -0.06em; max-width: 680px; }
.eyebrow { display: inline-flex; margin: 0 0 0.5rem; color: var(--accent); font-size: 0.78rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
.muted { color: var(--muted); max-width: 46rem; font-size: 1rem; line-height: 1.6; margin-bottom: 0; }
.meta-card, .summary-card, .notice, .filters, .finding-card, .empty-state {
  background: var(--panel);
  border: 1px solid var(--line);
}
.meta-card { border-radius: var(--radius); padding: 1rem; display: grid; gap: 0.42rem; align-content: end; overflow-wrap: anywhere; background: #0f172a; color: white; }
.meta-card span, .summary-card span, .summary-card small { color: var(--muted); font-size: 0.74rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
.meta-card span { color: #94a3b8; }
.meta-card strong { font-size: 0.92rem; font-weight: 600; }
.summary-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(135px, 1fr)); gap: 0.75rem; margin: 1rem 0; }
.summary-card { min-height: 112px; padding: 0.95rem; display: grid; gap: 0.14rem; align-content: space-between; border-radius: var(--radius); box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
.summary-card strong { font-size: 2.25rem; line-height: 1; letter-spacing: -0.05em; }
.summary-card.severity-critical strong { color: var(--critical); }
.summary-card.severity-high strong { color: var(--high); }
.summary-card.severity-medium strong { color: var(--medium); }
.summary-card.severity-low strong { color: var(--low); }
.summary-card.severity-obsolete strong { color: var(--obsolete); }
.action-panel, .inventory-panel, .score-panel { display: grid; grid-template-columns: minmax(220px, 0.55fr) 1.45fr; gap: 1rem; border: 1px solid var(--line); border-radius: var(--radius); background: rgba(255, 255, 255, 0.94); padding: 1rem; margin: 1rem 0; }
.section-kicker { margin: 0 0 0.3rem; color: var(--accent); font-size: 0.75rem; font-weight: 750; letter-spacing: 0.06em; text-transform: uppercase; }
.action-panel { margin-top: 1.25rem; background: #fbfcfc; }
.action-panel h2, .inventory-panel h2, .score-panel h2 { margin: 0; font-size: 1.35rem; letter-spacing: -0.04em; }
.action-panel h2 { font-size: 1.05rem; }
.action-panel .section-kicker { font-size: 0.68rem; }
.action-panel ol { margin: 0; padding-left: 1.15rem; display: grid; gap: 0.36rem; color: #344054; line-height: 1.45; font-size: 0.9rem; }
.action-panel li::marker { color: var(--accent); font-weight: 800; }
.inventory-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 0.7rem; }
.inventory-grid .summary-card { min-height: 104px; background: #fbfcfc; }
.score-panel { grid-template-columns: minmax(160px, 220px) 1fr; align-items: center; }
.score-orb { width: 9.2rem; height: 9.2rem; border-radius: 999px; display: grid; place-items: center; align-content: center; justify-self: center; background: conic-gradient(var(--accent) calc(var(--score) * 1%), #e8eef0 0); position: relative; color: var(--ink); }
.score-orb::after { content: ""; position: absolute; inset: 0.7rem; border-radius: inherit; background: white; border: 1px solid var(--line); }
.score-orb strong, .score-orb span { position: relative; z-index: 1; }
.score-orb strong { font-size: 2.4rem; line-height: 1; letter-spacing: -0.07em; }
.score-orb span { color: var(--muted); font-size: 0.72rem; font-weight: 750; text-transform: uppercase; letter-spacing: 0.04em; }
.score-copy p { color: #475467; line-height: 1.55; margin: 0.45rem 0 0.9rem; max-width: 60rem; }
.severity-chart { display: grid; gap: 0.5rem; }
.chart-row { display: grid; grid-template-columns: 5.4rem minmax(80px, 1fr) 2.3rem; gap: 0.65rem; align-items: center; font-size: 0.82rem; color: var(--muted); }
.chart-row > span { font-weight: 700; }
.chart-row > strong { color: var(--ink); text-align: right; }
.chart-track { height: 0.55rem; border-radius: 999px; background: #eef2f4; overflow: hidden; }
.chart-track i { display: block; height: 100%; border-radius: inherit; background: var(--obsolete); }
.chart-row.severity-critical .chart-track i { background: var(--critical); }
.chart-row.severity-high .chart-track i { background: var(--high); }
.chart-row.severity-medium .chart-track i { background: var(--medium); }
.chart-row.severity-low .chart-track i { background: var(--low); }
.notice { border-radius: 0.8rem; padding: 0.55rem 0.7rem; background: transparent; color: var(--muted); line-height: 1.45; font-size: 0.78rem; margin-top: 0.85rem; }
.notice strong { color: var(--ink); }
.notice a { color: var(--accent); font-weight: 650; }
.filters { margin: 1rem 0 0; padding: 0.8rem; display: grid; grid-template-columns: 2fr 1fr 1fr; gap: 0.65rem; align-items: end; background: rgba(255, 255, 255, 0.92); position: sticky; top: 0.75rem; z-index: 5; border-radius: var(--radius); box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08); backdrop-filter: blur(10px); }
label { color: var(--muted); display: grid; gap: 0.35rem; font-size: 0.76rem; font-weight: 700; letter-spacing: 0.02em; }
input, select, button { width: 100%; border: 1px solid var(--line-strong); border-radius: 0.7rem; background: var(--panel); color: var(--ink); padding: 0.68rem 0.75rem; font: inherit; }
input::placeholder { color: var(--subtle); }
button { cursor: pointer; font-size: 0.86rem; font-weight: 650; white-space: nowrap; }
button:hover { background: var(--panel-soft); }
button:active { transform: translateY(1px); }
button:focus, input:focus, select:focus { outline: 3px solid rgba(15, 118, 110, 0.18); border-color: var(--accent); }
.toolbar-result { color: var(--muted); margin: 0.75rem 0; font-size: 0.9rem; }
#visible-count { color: var(--ink); font-weight: 700; }
.findings {
  display: grid;
  gap: 0.62rem;
  max-height: min(760px, 64vh);
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: 0.1rem 0.55rem 0.1rem 0;
  scrollbar-color: var(--line-strong) transparent;
}
.finding-card { overflow: hidden; border-radius: var(--radius); background: rgba(255, 255, 255, 0.94); box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
.finding-card.severity-critical { border-left-color: var(--critical); }
.finding-card.severity-high { border-left-color: var(--high); }
.finding-card.severity-medium { border-left-color: var(--medium); }
.finding-card.severity-low { border-left-color: var(--low); }
.finding-card.severity-obsolete { border-left-color: var(--obsolete); }
.finding-card { border-left: 4px solid transparent; }

.finding-header { display: grid; grid-template-columns: auto auto minmax(0, 1fr); gap: 0.7rem; align-items: center; padding: 0.9rem 1rem; }
.finding-header strong { min-width: 0; font-size: 0.96rem; font-weight: 650; line-height: 1.45; }
.badge { border-radius: 999px; padding: 0.22rem 0.55rem; font-size: 0.72rem; font-weight: 750; text-transform: capitalize; background: var(--obsolete-soft); color: var(--obsolete); }
.severity-critical .badge { background: var(--critical-soft); color: var(--critical); }
.severity-high .badge { background: var(--high-soft); color: var(--high); }
.severity-medium .badge { background: var(--medium-soft); color: #854d0e; }
.severity-low .badge { background: var(--low-soft); color: var(--low); }
.severity-obsolete .badge { background: var(--obsolete-soft); color: var(--obsolete); }
.category { color: var(--muted); text-transform: capitalize; font-size: 0.82rem; background: var(--panel-soft); border: 1px solid var(--line); border-radius: 999px; padding: 0.2rem 0.5rem; }
.finding-body { border-top: 1px solid var(--line); padding: 1rem; display: grid; grid-template-columns: minmax(240px, 0.8fr) 1.2fr; gap: 1rem; background: #fbfcfc; }
.finding-body h3 { margin: 0 0 0.4rem; font-size: 0.76rem; color: var(--muted); text-transform: uppercase; letter-spacing: 0.05em; }
.finding-body p { margin: 0; color: #475467; line-height: 1.6; }
.credential-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.5rem; }
.credential-list li { background: var(--panel); border: 1px solid var(--line); border-radius: 0.8rem; padding: 0.7rem; display: grid; gap: 0.22rem; }
.credential-list strong { font-weight: 650; }
.credential-list span, .credential-list small { color: var(--muted); overflow-wrap: anywhere; }
code { color: var(--accent); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.empty-state { border-radius: var(--radius); padding: 2rem; text-align: center; color: var(--muted); }
.is-hidden { display: none; }
@media (max-width: 900px) {
  .hero, .finding-body, .action-panel, .inventory-panel, .score-panel { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .filters { grid-template-columns: 1fr; position: static; }
  .findings { max-height: none; overflow: visible; padding-right: 0; }
  .finding-header { grid-template-columns: 1fr; }
}
"""


def _render_script() -> str:
    return """
const searchInput = document.querySelector('#search');
const severityFilter = document.querySelector('#severity-filter');
const categoryFilter = document.querySelector('#category-filter');
const visibleCount = document.querySelector('#visible-count');
const cards = Array.from(document.querySelectorAll('.finding-card'));

function applyFilters() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const category = categoryFilter.value;
  let count = 0;

  for (const card of cards) {
    const matchesQuery = !query || card.dataset.search.includes(query);
    const matchesSeverity = severity === 'all' || card.dataset.severity === severity;
    const matchesCategory = category === 'all' || card.dataset.category === category;
    const visible = matchesQuery && matchesSeverity && matchesCategory;
    card.classList.toggle('is-hidden', !visible);
    if (visible) count += 1;
  }
  visibleCount.textContent = count;
}

searchInput.addEventListener('input', applyFilters);
severityFilter.addEventListener('change', applyFilters);
categoryFilter.addEventListener('change', applyFilters);
applyFilters();
"""
