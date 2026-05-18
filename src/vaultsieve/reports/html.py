from __future__ import annotations

from html import escape

from vaultsieve.analyzers.duplicates import duplicate_cleanup_plan
from vaultsieve.models import SEVERITY_ORDER, AuditReport, Finding

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
    overview = _render_overview(report, dashboard)
    action_plan = _render_action_plan(dashboard)
    finding_cards = _render_finding_cards(report, findings)
    initial_severity = "critical" if len(findings) > 250 and report.summary_by_severity["critical"] else "all"
    initial_filter_text = "Showing all findings" if initial_severity == "all" else f"Showing severity: {initial_severity}"
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

    {overview}

    {action_plan}

    <section class="affected-heading">
      <div>
        <p class="section-kicker">Affected entries</p>
        <h2>Selected findings</h2>
      </div>
      <p>Use an action button or the filters to inspect the accounts behind each issue.</p>
    </section>

    {_render_filters(findings, initial_severity)}

    <section class="active-filter" id="active-filter">{escape(initial_filter_text)}</section>

    <section class="toolbar-result">
      <span id="visible-count">{len(findings)}</span> visible findings
    </section>

    <section class="findings" id="findings">
      {finding_cards}
    </section>

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
    credential_map = report.credential_map()
    breached_passwords = {
        credential.password
        for finding in report.findings
        if finding.category == "breached"
        for credential_id in finding.credential_ids
        if (credential := credential_map.get(credential_id)) is not None and credential.password
    }
    for finding in report.findings:
        category_counts[finding.category] = category_counts.get(
            finding.category, 0) + 1

    cleanup_plan = duplicate_cleanup_plan(report.credentials)
    safe_duplicate_removals = sum(len(decision.remove_ids)
                                  for decision in cleanup_plan)
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
        "breached": category_counts.get("breached", 0),
        "breached_unique_passwords": len(breached_passwords),
        "empty": category_counts.get("empty", 0),
        "reuse": category_counts.get("reuse", 0),
        "insecure_http": category_counts.get("insecure_http", 0),
        "domain_concentration": category_counts.get("domain_concentration", 0),
        "domain_concentration_affected": sum(
            len(finding.credential_ids)
            for finding in report.findings
            if finding.category == "domain_concentration"
        ),
        "domain_missing": category_counts.get("domain_missing", 0),
        "obsolete_candidates": sum(
            len(finding.credential_ids)
            for finding in report.findings
            if finding.category == "domain_missing"
        ),
        "two_factor_not_stored": category_counts.get("two_factor_not_stored", 0),
        "service_known_breach": category_counts.get("service_known_breach", 0),
        "weak": category_counts.get("weak", 0),
    }


def _render_overview(report: AuditReport, dashboard: dict[str, int]) -> str:
    severity_chart = _render_severity_chart(report)
    return f"""
    <section class="overview-panel">
      <div class="overview-main">
        <div class="score-orb" style="--score: {dashboard['health_score']};">
          <strong>{dashboard['health_score']}</strong>
          <span>health score</span>
        </div>
        <div>
          <p class="section-kicker">Overview</p>
          <h2>Vault health at a glance</h2>
          <p class="overview-copy">The score is capped so repeated similar findings do not collapse large vaults to zero. Work through the action board below to improve it.</p>
        </div>
      </div>
      <div class="overview-lower overview-lower--single">
        <div>
          <p class="overview-label">Severity mix</p>
          {severity_chart}
        </div>
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


def _render_action_plan(dashboard: dict[str, int]) -> str:
    actions: list[str] = []
    step = 0
    # Card 1: Critical passwords (breached + empty)
    critical_total = dashboard["breached"] + dashboard["empty"]
    if critical_total:
        parts: list[str] = []
        if dashboard["breached"]:
            parts.append(f"{_count(dashboard['breached'], 'breached entry', 'breached entries')}")
        if dashboard["empty"]:
            parts.append(f"{_count(dashboard['empty'], 'empty password')}")
        step += 1
        actions.append(_action_card(
            str(step),
            "Fix critical passwords",
            " + ".join(parts),
            "Breached or missing passwords",
            "Rotate breached passwords first, then add passwords to empty entries. One unique-password change may fix many rows.",
            "breached,empty",
            "critical",
        ))
    # Card 2: Password reuse
    if dashboard["reuse"]:
        step += 1
        actions.append(_action_card(
            str(step),
            "Break password reuse",
            _count(dashboard["reuse"], "group"),
            "Same secret elsewhere",
            "Start with reused passwords that also appear in critical or high-risk services, then rerun the audit.",
            "reuse",
            "high",
        ))
    # Card 3: Duplicates
    if dashboard["safe_duplicate_removals"]:
        step += 1
        actions.append(_action_card(
            str(step),
            "Create a clean copy",
            f"{dashboard['safe_duplicate_removals']} removable",
            "Safe exact duplicates",
            "Use clean output after reviewing keepers. VaultSieve writes a new file and never edits the original export.",
            "duplicate",
            "high",
        ))
    # Card 4: Strengthen security (weak + insecure_http + 2FA)
    medium_items: list[str] = []
    medium_categories: list[str] = []
    if dashboard["weak"]:
        medium_items.append(f"{_count(dashboard['weak'], 'weak password')}")
        medium_categories.append("weak")
    if dashboard["insecure_http"]:
        medium_items.append(f"{_count(dashboard['insecure_http'], 'insecure URL')}")
        medium_categories.append("insecure_http")
    if dashboard["two_factor_not_stored"]:
        medium_items.append(f"{_count(dashboard['two_factor_not_stored'], 'missing 2FA')}")
        medium_categories.append("two_factor_not_stored")
    if medium_items:
        step += 1
        actions.append(_action_card(
            str(step),
            "Strengthen security",
            " · ".join(medium_items),
            "Weak passwords, insecure URLs, and 2FA gaps",
            "Upgrade weak passwords, switch URLs to HTTPS, and confirm 2FA is enabled where supported.",
            ",".join(medium_categories),
            "medium",
        ))
    # Card 5: Review services (domain_concentration + service_known_breach)
    low_items: list[str] = []
    low_categories: list[str] = []
    if dashboard["domain_concentration"]:
        low_items.append(f"{_count(dashboard['domain_concentration'], 'cluster')}")
        low_categories.append("domain_concentration")
    if dashboard["service_known_breach"]:
        low_items.append(f"{_count(dashboard['service_known_breach'], 'breached service')}")
        low_categories.append("service_known_breach")
    if low_items:
        step += 1
        actions.append(_action_card(
            str(step),
            "Review services",
            " · ".join(low_items),
            "Account clusters and breach history",
            "Trim domains with many accounts and check services with public breach history. Prioritize old or reused passwords.",
            ",".join(low_categories),
            "low",
        ))
    # Card 6: Obsolete services
    if dashboard["domain_missing"]:
        step += 1
        actions.append(_action_card(
            str(step),
            "Confirm obsolete services",
            _count(dashboard["domain_missing"], "group"),
            f"{_count(dashboard['obsolete_candidates'], 'entry', 'entries')} affected",
            "DNS did not resolve. Confirm manually before deleting; temporary DNS failures can happen.",
            "domain_missing",
            "obsolete",
        ))
    if not actions:
        actions.append(
            "<article class=\"action-card\"><strong>No immediate action required</strong>"
            "<p>The enabled checks did not find anything that needs attention.</p></article>"
        )
    return f"""
    <section class="action-panel">
      <div>
        <p class="section-kicker">Recommended next steps</p>
        <h2>Action board</h2>
        <p class="action-help">Work top to bottom. Use each button to filter the affected-entry table, fix a batch, then rerun the audit.</p>
      </div>
      <div class="action-grid">{''.join(actions)}</div>
    </section>
    """


def _action_card(
    step: str,
    title: str,
    metric: str,
    context: str,
    guidance: str,
    categories: str,
    severity: str,
) -> str:
    return f"""
    <article class="action-card severity-{escape(severity)}">
      <div class="action-card-top">
        <span class="action-step">{escape(step)}</span>
        <span class="badge">{escape(severity)}</span>
      </div>
      <h3>{escape(title)}</h3>
      <strong>{escape(metric)}</strong>
      <small>{escape(context)}</small>
      <p>{escape(guidance)}</p>
      <button type="button" data-category-filter="{escape(categories, quote=True)}">Show affected</button>
    </article>
    """


def _count(count: int, singular: str, plural: str | None = None) -> str:
    noun = singular if count == 1 else plural or f"{singular}s"
    return f"{count} {noun}"


def _render_attribution(report: AuditReport) -> str:
    parts: list[str] = []
    if any(finding.category == "two_factor_not_stored" for finding in report.findings):
        parts.append(
            "Data sourced from <a href=\"https://2fa.directory/\">2FA Directory</a> by <a href=\"https://github.com/2factorauth/\">2factorauth</a>.")
    if any(finding.category == "service_known_breach" for finding in report.findings):
        parts.append(
            "Breach catalogue data sourced from <a href=\"https://haveibeenpwned.com/\">Have I Been Pwned</a>.")
    return " " + " ".join(parts) if parts else ""


def _render_filters(findings: list[Finding], initial_severity: str = "all") -> str:
    categories = sorted({finding.category for finding in findings})
    severity_options = ''.join(
        f'<option value="{escape(severity)}"{" selected" if severity == initial_severity else ""}>{escape(severity.title())}</option>'
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
      <button type="button" id="clear-filters">Clear filters</button>
    </section>
    """


def _render_finding_cards(report: AuditReport, findings: list[Finding]) -> str:
    if not findings:
        return "<div class=\"empty-state\">No findings detected.</div>"

    credential_map = report.credential_map()
    rows: list[str] = []
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
                f"<span><strong>{escape(credential.name or '(unnamed)')}</strong> "
                f"<small>{escape(credential.username or '(no username)')}</small> "
                f"<code>{escape(credential.id)}</code> "
                f"<em>{escape(urls)}</em></span>"
            )

        search_text = escape(" ".join(search_parts).lower(), quote=True)
        affected_count = len(finding.credential_ids)
        rows.append(
            f"""
            <tr class="finding-row severity-{escape(finding.severity)}" data-severity="{escape(finding.severity)}" data-category="{escape(finding.category)}" data-search="{search_text}">
              <td><span class="badge">{escape(finding.severity)}</span></td>
              <td><span class="category">{escape(finding.category.replace('_', ' '))}</span></td>
              <td class="issue-cell"><strong>{escape(finding.explanation)}</strong><p>{escape(finding.recommendation)}</p></td>
              <td class="count-cell">{affected_count}</td>
              <td class="affected-cell">{''.join(credential_items)}</td>
            </tr>
            """
        )
    return f"""
    <div class="findings-table-wrap">
      <table class="findings-table">
        <thead>
          <tr>
            <th>Severity</th>
            <th>Category</th>
            <th>Issue / recommendation</th>
            <th>Affected</th>
            <th>Entries</th>
          </tr>
        </thead>
        <tbody>{''.join(rows)}</tbody>
      </table>
    </div>
    """


def _render_styles() -> str:
    return """
:root {
  color-scheme: light;
  --page: #f8f9fb;
  --panel: #ffffff;
  --panel-soft: #f4f5f7;
  --ink: #0f1729;
  --ink-secondary: #344054;
  --muted: #667085;
  --subtle: #98a2b3;
  --line: #e4e7ec;
  --line-strong: #c8cfd8;
  --accent: #0d9488;
  --accent-hover: #0f766e;
  --accent-soft: #e6f5f2;
  --critical: #dc2626;
  --critical-soft: #fef2f2;
  --high: #ea580c;
  --high-soft: #fff7ed;
  --medium: #ca8a04;
  --medium-soft: #fefce8;
  --low: #2563eb;
  --low-soft: #eff6ff;
  --obsolete: #6b7280;
  --obsolete-soft: #f3f4f6;
  --shadow-sm: 0 1px 3px rgba(15,23,42,.06);
  --shadow: 0 4px 24px rgba(15,23,42,.07);
  --shadow-lg: 0 12px 40px rgba(15,23,42,.1);
  --radius: 14px;
  --radius-sm: 10px;
  --transition: 0.18s ease;
}
*, *::before, *::after { box-sizing: border-box; }
html { scroll-behavior: smooth; }
body {
  margin: 0; min-height: 100vh;
  background:
    radial-gradient(circle, rgba(15,23,42,.1) 1px, transparent 1.4px),
    linear-gradient(170deg, #eef7f5 0%, var(--page) 28%, var(--page) 100%);
  background-size: 22px 22px, auto;
  color: var(--ink);
  font-family: ui-sans-serif, -apple-system, BlinkMacSystemFont, "Segoe UI", system-ui, sans-serif;
  font-size: 15px; line-height: 1.6;
  -webkit-font-smoothing: antialiased;
}

/* === Shell === */
.shell { width: min(1140px, calc(100% - 2.5rem)); margin: 0 auto; padding: 2.5rem 0 3rem; display: grid; gap: 1.25rem; }

/* === Hero === */
.hero {
  display: grid; grid-template-columns: 1fr auto; gap: 1.5rem; align-items: end;
  border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px);
  background: var(--panel); box-shadow: var(--shadow);
  padding: 1.75rem 1.5rem;
}
.brand-lockup { display: flex; align-items: center; gap: 0.6rem; margin-bottom: 1rem; }
.brand-icon { width: 2.2rem; height: 2.2rem; object-fit: contain; border-radius: 0.55rem; padding: 0; display: block; }
.brand-name { font-size: 0.95rem; font-weight: 700; letter-spacing: -0.01em; }
.eyebrow { display: inline-block; margin: 0 0 0.35rem; color: var(--accent); font-size: 0.7rem; font-weight: 700; letter-spacing: 0.08em; text-transform: uppercase; }
.hero h2 { margin: 0 0 0.35rem; font-size: 1.5rem; font-weight: 800; letter-spacing: -0.035em; line-height: 1.15; }
.muted { color: var(--muted); max-width: 44rem; font-size: 0.88rem; line-height: 1.55; margin: 0; }
.meta-card { border-radius: var(--radius-sm); padding: 0.85rem 1rem; display: grid; gap: 0.3rem; align-content: end; overflow-wrap: anywhere; background: var(--ink); color: white; min-width: 240px; }
.meta-card span { color: #94a3b8; font-size: 0.68rem; font-weight: 700; letter-spacing: 0.04em; text-transform: uppercase; }
.meta-card strong { font-size: 0.85rem; font-weight: 600; }

/* === Section headings === */
.section-kicker { margin: 0 0 0.2rem; color: var(--accent); font-size: 0.68rem; font-weight: 750; letter-spacing: 0.07em; text-transform: uppercase; }

/* === Overview === */
.overview-panel {
  border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px);
  background: var(--panel); box-shadow: var(--shadow-sm);
  padding: 1.5rem; display: grid; gap: 1.35rem;
}
.overview-main { display: grid; grid-template-columns: auto 1fr; gap: 1.5rem; align-items: center; }
.overview-main h2 { margin: 0; font-size: 1.25rem; font-weight: 800; letter-spacing: -0.03em; }
.overview-copy { color: var(--ink-secondary); line-height: 1.55; margin: 0.3rem 0 0; font-size: 0.88rem; max-width: 64rem; }
.overview-lower { display: grid; grid-template-columns: 1fr; gap: 1rem; }
.overview-lower--single { grid-template-columns: 1fr; }
.overview-label { margin: 0 0 0.5rem; color: var(--muted); font-size: 0.68rem; font-weight: 800; letter-spacing: 0.06em; text-transform: uppercase; }

/* === Score orb === */
.score-orb {
  width: 8rem; height: 8rem; border-radius: 999px;
  display: grid; place-items: center; align-content: center; justify-self: center;
  background: conic-gradient(var(--accent) calc(var(--score) * 1%), var(--line) 0);
  position: relative; color: var(--ink);
}
.score-orb::after { content: ""; position: absolute; inset: 0.55rem; border-radius: inherit; background: var(--panel); box-shadow: inset 0 0 0 1px var(--line); }
.score-orb strong, .score-orb span { position: relative; z-index: 1; }
.score-orb strong { font-size: 2.1rem; line-height: 1; letter-spacing: -0.06em; font-weight: 800; }
.score-orb span { color: var(--muted); font-size: 0.65rem; font-weight: 750; text-transform: uppercase; letter-spacing: 0.04em; }

/* === Severity chart === */
.severity-chart { display: grid; gap: 0.45rem; }
.chart-row { display: grid; grid-template-columns: 5rem 1fr 2rem; gap: 0.6rem; align-items: center; font-size: 0.8rem; color: var(--muted); }
.chart-row > span { font-weight: 700; }
.chart-row > strong { color: var(--ink); text-align: right; font-size: 0.82rem; }
.chart-track { height: 0.5rem; border-radius: 999px; background: var(--panel-soft); overflow: hidden; }
.chart-track i { display: block; height: 100%; border-radius: inherit; background: var(--obsolete); transition: width 0.6s ease; }
.chart-row.severity-critical .chart-track i { background: var(--critical); }
.chart-row.severity-high .chart-track i { background: var(--high); }
.chart-row.severity-medium .chart-track i { background: var(--medium); }
.chart-row.severity-low .chart-track i { background: var(--low); }

/* === Action panel === */
.action-panel {
  display: grid; grid-template-columns: minmax(200px, 0.38fr) 1fr; gap: 1.25rem;
  border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px);
  background: var(--panel-soft); box-shadow: var(--shadow-sm);
  padding: 1.5rem; align-items: start;
}
.action-panel h2 { margin: 0; font-size: 1.25rem; font-weight: 800; letter-spacing: -0.03em; }
.action-panel .section-kicker { font-size: 0.65rem; }
.action-help { color: var(--ink-secondary); line-height: 1.5; margin: 0.4rem 0 0; font-size: 0.85rem; }
.action-grid { display: grid; grid-template-columns: repeat(auto-fill, minmax(210px, 1fr)); gap: 0.6rem; }
.action-card {
  border: 1px solid var(--line);
  border-radius: var(--radius-sm); background: var(--panel);
  padding: 0.85rem; display: grid; gap: 0.3rem; align-content: start; min-height: 195px;
  transition: box-shadow var(--transition), transform var(--transition);
}
.action-card:hover { box-shadow: var(--shadow); transform: translateY(-1px); }
.action-card-top { display: flex; justify-content: space-between; gap: 0.5rem; align-items: center; }
.action-step { width: 1.4rem; height: 1.4rem; border-radius: 999px; display: inline-grid; place-items: center; background: var(--ink); color: white; font-size: 0.7rem; font-weight: 800; }
.action-card h3 { margin: 0; font-size: 0.88rem; font-weight: 700; letter-spacing: -0.015em; }
.action-card strong { font-size: 1.3rem; line-height: 1; letter-spacing: -0.05em; font-weight: 800; }
.action-card small { color: var(--muted); font-weight: 700; text-transform: uppercase; letter-spacing: 0.03em; font-size: 0.65rem; }
.action-card p { margin: 0; color: var(--ink-secondary); line-height: 1.4; font-size: 0.78rem; }
.action-card button {
  align-self: end; margin-top: 0.25rem; padding: 0.45rem 0.6rem; font-size: 0.76rem;
  background: var(--ink); color: white; border-color: var(--ink);
  border-radius: 0.55rem; font-weight: 700;
}
.action-card button:hover { background: #1e293b; border-color: #1e293b; }

/* === Affected heading === */
.affected-heading { display: flex; justify-content: space-between; gap: 1rem; align-items: end; }
.affected-heading h2 { margin: 0; font-size: 1.15rem; font-weight: 800; letter-spacing: -0.03em; }
.affected-heading p { margin: 0; color: var(--muted); font-size: 0.85rem; }

/* === Filters === */
.filters {
  padding: 0.75rem 1rem; display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 0.6rem; align-items: end;
  background: rgba(255,255,255,.92); position: sticky; top: 0; z-index: 5;
  border: 1px solid var(--line); border-radius: var(--radius);
  box-shadow: var(--shadow); backdrop-filter: blur(12px);
}
.active-filter { color: var(--muted); margin: 0; font-size: 0.82rem; }
label { color: var(--muted); display: grid; gap: 0.28rem; font-size: 0.7rem; font-weight: 700; letter-spacing: 0.02em; }
input, select, button { width: 100%; border: 1px solid var(--line-strong); border-radius: 0.55rem; background: var(--panel); color: var(--ink); padding: 0.55rem 0.65rem; font: inherit; font-size: 0.86rem; transition: border-color var(--transition), box-shadow var(--transition), background var(--transition); }
input::placeholder { color: var(--subtle); }
button { cursor: pointer; font-size: 0.82rem; font-weight: 700; white-space: nowrap; }
button:hover { background: var(--panel-soft); }
button:active { transform: translateY(1px); }
button:focus-visible, input:focus-visible, select:focus-visible { outline: 2px solid var(--accent); outline-offset: 1px; border-color: var(--accent); }
#clear-filters { background: transparent; border-color: var(--line); color: var(--muted); }
#clear-filters:hover { background: var(--panel-soft); color: var(--ink); }

/* === Results bar === */
.toolbar-result { color: var(--muted); margin: 0; font-size: 0.85rem; }
#visible-count { color: var(--ink); font-weight: 800; }

/* === Findings table === */
.findings {
  max-height: min(780px, 68vh);
  overflow-y: auto; overscroll-behavior: contain;
  padding-right: 0.25rem;
  scrollbar-width: thin; scrollbar-color: var(--line-strong) transparent;
}
.findings-table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius); background: var(--panel); box-shadow: var(--shadow-sm); }
.findings-table { width: 100%; border-collapse: collapse; min-width: 900px; font-size: 0.84rem; }
.findings-table th {
  position: sticky; top: 0; z-index: 1; text-align: left;
  color: var(--muted); background: var(--panel-soft);
  border-bottom: 1px solid var(--line); padding: 0.6rem 0.75rem;
  font-size: 0.68rem; font-weight: 700; text-transform: uppercase; letter-spacing: 0.05em;
}
.findings-table td { vertical-align: top; border-top: 1px solid var(--line); padding: 0.65rem 0.75rem; transition: background var(--transition); }
.findings-table tbody tr:first-child td { border-top: 0; }
.findings-table th:nth-child(2), .findings-table td:nth-child(2) { min-width: 140px; }
.finding-row:hover td { background: var(--panel-soft); }
.finding-row.severity-critical:hover td { background: var(--critical-soft); }
.finding-row.severity-high:hover td { background: var(--high-soft); }
.issue-cell { min-width: 260px; }
.issue-cell strong { display: block; line-height: 1.35; font-weight: 650; }
.issue-cell p { margin: 0.2rem 0 0; color: var(--ink-secondary); line-height: 1.45; font-size: 0.82rem; }
.count-cell { text-align: center; font-weight: 800; font-size: 0.95rem; }
.affected-cell { min-width: 280px; display: grid; gap: 0.3rem; }
.affected-cell span { display: block; line-height: 1.35; }
.affected-cell small, .affected-cell em { color: var(--muted); font-style: normal; overflow-wrap: anywhere; font-size: 0.8rem; }

/* === Badges & pills === */
.badge { border-radius: 999px; padding: 0.18rem 0.5rem; font-size: 0.68rem; font-weight: 750; text-transform: capitalize; background: var(--obsolete-soft); color: var(--obsolete); }
.severity-critical .badge { background: var(--critical-soft); color: var(--critical); }
.severity-high .badge { background: var(--high-soft); color: var(--high); }
.severity-medium .badge { background: var(--medium-soft); color: #854d0e; }
.severity-low .badge { background: var(--low-soft); color: var(--low); }
.severity-obsolete .badge { background: var(--obsolete-soft); color: var(--obsolete); }
.category { color: var(--muted); text-transform: capitalize; font-size: 0.78rem; background: var(--panel-soft); border-radius: 999px; padding: 0.15rem 0.45rem; display: inline-block; white-space: nowrap; }

/* === Utilities === */
code { color: var(--accent); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.82em; }
.notice { border: 1px solid var(--line); border-radius: var(--radius-sm); padding: 0.65rem 0.85rem; background: var(--panel-soft); color: var(--muted); line-height: 1.5; font-size: 0.78rem; }
.notice strong { color: var(--ink); }
.notice a { color: var(--accent); font-weight: 650; text-decoration: none; }
.notice a:hover { text-decoration: underline; }
.empty-state { border-radius: var(--radius); padding: 2.5rem; text-align: center; color: var(--muted); background: var(--panel); }
.is-hidden { display: none; }

/* === Responsive === */
@media (max-width: 900px) {
  .hero, .action-panel { grid-template-columns: 1fr; }
  .overview-main, .overview-lower { grid-template-columns: 1fr; }
  .affected-heading { display: grid; align-items: start; }
  .filters { grid-template-columns: 1fr; position: static; box-shadow: var(--shadow-sm); }
  .findings { max-height: none; overflow: visible; padding-right: 0; }
  .category-guide { grid-template-columns: 1fr 1fr; }
}
@media (max-width: 600px) {
  .shell { width: calc(100% - 1.5rem); padding: 1.5rem 0 2rem; }
  .hero { padding: 1.25rem; }
  .category-guide { grid-template-columns: 1fr; }
  .action-grid { grid-template-columns: 1fr; }
}
"""


def _render_script() -> str:
    return """
const searchInput = document.querySelector('#search');
const severityFilter = document.querySelector('#severity-filter');
const categoryFilter = document.querySelector('#category-filter');
const visibleCount = document.querySelector('#visible-count');
const activeFilter = document.querySelector('#active-filter');
const cards = Array.from(document.querySelectorAll('.finding-row'));
const categoryButtons = Array.from(document.querySelectorAll('[data-category-filter]'));
const clearFiltersButton = document.querySelector('#clear-filters');

function applyFilters() {
  const query = searchInput.value.trim().toLowerCase();
  const severity = severityFilter.value;
  const category = categoryFilter.value;
  const multi = categoryFilter.dataset.multi;
  const multiSet = multi ? new Set(multi.split(',')) : null;
  let count = 0;

  for (const card of cards) {
    const matchesQuery = !query || card.dataset.search.includes(query);
    const matchesSeverity = severity === 'all' || card.dataset.severity === severity;
    const matchesCategory = multiSet ? multiSet.has(card.dataset.category) : (category === 'all' || card.dataset.category === category);
    const visible = matchesQuery && matchesSeverity && matchesCategory;
    card.classList.toggle('is-hidden', !visible);
    if (visible) count += 1;
  }
  visibleCount.textContent = count;
  const parts = [];
  if (severity !== 'all') parts.push(`severity: ${severity}`);
  if (multiSet) parts.push(`categories: ${[...multiSet].join(', ').replaceAll('_', ' ')}`);
  else if (category !== 'all') parts.push(`category: ${category.replaceAll('_', ' ')}`);
  if (query) parts.push(`search: ${query}`);
  activeFilter.textContent = parts.length ? `Showing ${parts.join(' · ')}` : 'Showing all findings';
}

searchInput.addEventListener('input', applyFilters);
severityFilter.addEventListener('change', () => { delete categoryFilter.dataset.multi; applyFilters(); });
categoryFilter.addEventListener('change', () => { delete categoryFilter.dataset.multi; applyFilters(); });
clearFiltersButton.addEventListener('click', () => {
  searchInput.value = '';
  severityFilter.value = 'all';
  categoryFilter.value = 'all';
  delete categoryFilter.dataset.multi;
  applyFilters();
});
for (const button of categoryButtons) {
  button.addEventListener('click', () => {
    const cats = button.dataset.categoryFilter;
    if (cats.includes(',')) {
      categoryFilter.value = 'all';
      categoryFilter.dataset.multi = cats;
    } else {
      categoryFilter.value = cats;
      delete categoryFilter.dataset.multi;
    }
    severityFilter.value = 'all';
    searchInput.value = '';
    applyFilters();
    document.querySelector('#findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}
applyFilters();
"""
