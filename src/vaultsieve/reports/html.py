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
    cleanup_plan = _render_cleanup_plan(report, dashboard)
    category_dashboard = _render_category_dashboard(report, dashboard)
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

    {generated_summary}

    {inventory}

    {score_panel}

    {category_dashboard}

    {action_plan}

    {cleanup_plan}

    <section class="affected-heading">
      <div>
        <p class="section-kicker">Affected entries</p>
        <h2>Selected findings</h2>
      </div>
      <p>Use a category card or the filters to inspect the accounts behind each issue.</p>
    </section>

    {filters}

    <section class="active-filter" id="active-filter">Showing all findings</section>

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
    for finding in report.findings:
        category_counts[finding.category] = category_counts.get(
            finding.category, 0) + 1

    cleanup_plan = duplicate_cleanup_plan(report.credentials)
    safe_duplicate_removals = sum(len(decision.remove_ids)
                                  for decision in cleanup_plan)
    ambiguous_duplicate_groups = sum(
        1 for decision in cleanup_plan if not decision.remove_ids)
    web_entries = sum(1 for credential in report.credentials if any(
        extract_domain(url) for url in credential.urls))
    app_entries = sum(
        1
        for credential in report.credentials
        if credential.urls and not any(extract_domain(url) for url in credential.urls)
    )
    passkeys = sum(
        1 for credential in report.credentials if credential.has_passkey)
    ssh_keys = sum(
        1 for credential in report.credentials if credential.is_ssh_key)
    highest_risk = category_counts.get(
        "breached", 0) + category_counts.get("empty", 0)
    needs_review = (
        category_counts.get("reuse", 0)
        + category_counts.get("domain_missing", 0)
        + category_counts.get("two_factor_not_stored", 0)
        + category_counts.get("service_known_breach", 0)
        + category_counts.get("insecure_http", 0)
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
        "insecure_http": category_counts.get("insecure_http", 0),
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


def _render_summary(report: AuditReport, dashboard: dict[str, int]) -> str:
    items = [
        ("Health", str(dashboard["health_score"]), "score"),
        ("Credentials", str(len(report.credentials)), "imported"),
        ("Findings", str(len(report.findings)), "detected"),
        ("Highest risk", str(dashboard["highest_risk"]), "urgent"),
        ("Needs review", str(dashboard["needs_review"]), "manual"),
        ("Safe cleanup", str(
            dashboard["safe_duplicate_removals"]), "removable"),
    ]
    pills = "".join(
        f"<div class=\"summary-pill\"><span>{escape(label)}</span><strong>{escape(value)}</strong><small>{escape(unit)}</small></div>"
        for label, value, unit in items
    )
    return f"""
    <section class="summary-grid">
      <div>
        <p class="section-kicker">Audit summary</p>
        <h2>What needs attention</h2>
      </div>
      <div class="summary-pills">{pills}</div>
    </section>
    """


def _render_category_dashboard(report: AuditReport, dashboard: dict[str, int]) -> str:
    category_counts: dict[str, int] = {}
    affected_counts: dict[str, int] = {}
    for finding in report.findings:
        category_counts[finding.category] = category_counts.get(
            finding.category, 0) + 1
        affected_counts[finding.category] = affected_counts.get(
            finding.category, 0) + len(finding.credential_ids)

    cards = [
        _category_card(
            "Compromised passwords",
            "breached",
            affected_counts.get("breached", 0),
            "critical",
            "Found in breach data.",
            "Change immediately.",
        ),
        _category_card(
            "Reused passwords",
            "reuse",
            category_counts.get("reuse", 0),
            "high",
            "Same password, different entries.",
            "Rotate to unique passwords.",
            "groups",
        ),
        _category_card(
            "Weak passwords",
            "weak",
            affected_counts.get("weak", 0),
            "medium",
            "Short or easy to guess.",
            "Replace after urgent fixes.",
        ),
        _category_card(
            "Insecure websites",
            "insecure_http",
            affected_counts.get("insecure_http", 0),
            "medium",
            "Entry uses http://.",
            "Switch to HTTPS if possible.",
        ),
        _category_card(
            "2FA not stored",
            "two_factor_not_stored",
            affected_counts.get("two_factor_not_stored", 0),
            "medium",
            "TOTP supported, not stored here.",
            "Confirm 2FA is enabled.",
        ),
        _category_card(
            "Breached services",
            "service_known_breach",
            affected_counts.get("service_known_breach", 0),
            "low",
            "Public breach history. Not email proof.",
            "Review old/reused passwords.",
        ),
        _category_card(
            "Missing domains",
            "domain_missing",
            affected_counts.get("domain_missing", 0),
            "obsolete",
            "Domain did not resolve.",
            "Confirm before deleting.",
        ),
        _category_card(
            "Safe duplicate cleanup",
            "duplicate",
            dashboard["safe_duplicate_removals"],
            "high",
            "Exact duplicates with a keeper.",
            "Create clean output.",
            "removable",
        ),
        _category_card(
            "Inventory context",
            "all",
            len(report.credentials),
            "low",
            "Web, app, passkey, SSH mix.",
            "Use for coverage context.",
            "entries",
        ),
    ]
    return f"""
    <section class="category-dashboard">
      <div class="category-dashboard-heading">
        <div>
          <p class="section-kicker">Category dashboard</p>
          <h2>Inspect by category</h2>
        </div>
        <button type="button" class="category-reset" data-category-filter="all">Show all findings</button>
      </div>
      <div class="category-grid">{''.join(cards)}</div>
    </section>
    """


def _category_card(
    title: str,
    category: str,
    count: int,
    severity: str,
    description: str,
    action: str,
    unit: str = "affected",
) -> str:
    disabled = " disabled" if count == 0 and category != "all" else ""
    return f"""
    <article class="category-card severity-{escape(severity)}{disabled}">
      <div class="category-card-top">
        <span class="badge">{escape(severity)}</span>
        <strong>{count}</strong>
        <small>{escape(unit)}</small>
      </div>
      <h3>{escape(title)}</h3>
      <p>{escape(description)}</p>
      <em>{escape(action)}</em>
      <button type="button" data-category-filter="{escape(category, quote=True)}">View affected</button>
    </article>
    """


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
        actions.append(
            f"Change {dashboard['breached']} breached password entries first.")
    if dashboard["empty"]:
        actions.append(f"Fix {dashboard['empty']} empty password entries.")
    if dashboard["reuse"]:
        actions.append(
            f"Review {dashboard['reuse']} password reuse groups and rotate reused passwords.")
    if dashboard["safe_duplicate_removals"]:
        actions.append(
            f"Create a clean output to remove {dashboard['safe_duplicate_removals']} safe exact duplicates.")
    if dashboard["domain_missing"]:
        actions.append(
            f"Review {dashboard['domain_missing']} missing-domain groups before deleting obsolete entries.")
    if dashboard["insecure_http"]:
        actions.append(
            f"Update {dashboard['insecure_http']} entries that still use insecure http:// URLs.")
    if dashboard["two_factor_not_stored"]:
        actions.append(
            f"Confirm 2FA on {dashboard['two_factor_not_stored']} TOTP-capable services not stored in this vault.")
    if dashboard["service_known_breach"]:
        actions.append(
            f"Review {dashboard['service_known_breach']} services with public breach history.")
    if dashboard["weak"]:
        actions.append(
            "Replace weak passwords after critical and reuse issues are handled.")
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
        ("Web entries", dashboard["web_entries"],
         "Checked for resolvable domains when enabled"),
        ("App entries", dashboard["app_entries"],
         "Skipped from web domain checks"),
        ("Passkeys", dashboard["passkeys"],
         "Skipped from empty-password warnings"),
        ("SSH keys", dashboard["ssh_keys"],
         "Skipped from web password/domain checks"),
        ("Ambiguous duplicates",
         dashboard["ambiguous_duplicate_groups"], "Kept because no clear keeper exists"),
    ]
    cards = "".join(
        f"<div class=\"summary-pill\"><span>{escape(title)}</span><strong>{value}</strong><small>{escape(subtitle)}</small></div>"
        for title, value, subtitle in items
    )
    return f"""
    <section class="inventory-panel">
      <div>
        <p class="section-kicker">Inventory</p>
        <h2>What VaultSieve understood</h2>
      </div>
      <div class="summary-pills">{cards}</div>
    </section>
    """


def _render_cleanup_plan(report: AuditReport, dashboard: dict[str, int]) -> str:
    duplicate_plan = duplicate_cleanup_plan(report.credentials)
    safe_groups = sum(1 for decision in duplicate_plan if decision.remove_ids)
    cards = [
        _cleanup_card(
            "Safe duplicate removals",
            dashboard["safe_duplicate_removals"],
            f"{safe_groups} exact duplicate groups have a clear keeper.",
        ),
        _cleanup_card(
            "Ambiguous duplicates kept",
            dashboard["ambiguous_duplicate_groups"],
            "Kept because metadata score is tied or no safe keeper exists.",
        ),
        _cleanup_card(
            "Obsolete candidates",
            dashboard["obsolete_candidates"],
            "Domain-missing entries can be removed with clean mode obsolete or all.",
        ),
    ]
    return f"""
    <section class="cleanup-panel">
      <div>
        <p class="section-kicker">Cleanup plan</p>
        <h2>What can be cleaned safely</h2>
      </div>
      <div class="cleanup-grid">{''.join(cards)}</div>
    </section>
    """


def _cleanup_card(title: str, value: int, description: str) -> str:
    return f"""
    <article class="cleanup-card">
      <span>{escape(title)}</span>
      <strong>{value}</strong>
      <small>{escape(description)}</small>
    </article>
    """


def _render_attribution(report: AuditReport) -> str:
    parts: list[str] = []
    if any(finding.category == "two_factor_not_stored" for finding in report.findings):
        parts.append(
            "Data sourced from <a href=\"https://2fa.directory/\">2FA Directory</a> by <a href=\"https://github.com/2factorauth/\">2factorauth</a>.")
    if any(finding.category == "service_known_breach" for finding in report.findings):
        parts.append(
            "Breach catalogue data sourced from <a href=\"https://haveibeenpwned.com/\">Have I Been Pwned</a>.")
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
.summary-grid { display: grid; grid-template-columns: minmax(190px, 0.38fr) 1fr; gap: 1rem; align-items: center; margin: 1rem 0; border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px); background: rgba(255, 255, 255, 0.94); padding: 1rem; }
.summary-grid h2 { margin: 0; font-size: 1.35rem; letter-spacing: -0.04em; }
.summary-pills { display: grid; grid-template-columns: repeat(6, minmax(0, 1fr)); gap: 0.55rem; }
.summary-pill { border: 1px solid var(--line); border-radius: 0.9rem; background: #fbfcfc; padding: 0.68rem 0.72rem; display: grid; gap: 0.08rem; min-width: 0; }
.summary-pill span, .summary-pill small { color: var(--muted); font-size: 0.68rem; font-weight: 700; letter-spacing: 0.03em; text-transform: uppercase; white-space: nowrap; overflow: hidden; text-overflow: ellipsis; }
.summary-pill strong { color: var(--ink); font-size: 1.45rem; line-height: 1; letter-spacing: -0.06em; }
.inventory-pill { min-height: 118px; align-content: space-between; padding: 0.9rem; }
.inventory-pill span { white-space: normal; }
.inventory-pill small { white-space: normal; overflow: visible; text-overflow: clip; line-height: 1.3; text-transform: none; letter-spacing: 0; font-weight: 600; }
.inventory-pill strong { font-size: 1.85rem; }
.summary-card { min-height: 112px; padding: 0.95rem; display: grid; gap: 0.14rem; align-content: space-between; border-radius: var(--radius); box-shadow: 0 1px 2px rgba(15, 23, 42, 0.04); }
.summary-card strong { font-size: 2.25rem; line-height: 1; letter-spacing: -0.05em; }
.summary-card.severity-critical strong { color: var(--critical); }
.summary-card.severity-high strong { color: var(--high); }
.summary-card.severity-medium strong { color: var(--medium); }
.summary-card.severity-low strong { color: var(--low); }
.summary-card.severity-obsolete strong { color: var(--obsolete); }
.action-panel, .score-panel, .cleanup-panel { display: grid; grid-template-columns: minmax(220px, 0.55fr) 1.45fr; gap: 1rem; border: 1px solid var(--line); border-radius: var(--radius); background: rgba(255, 255, 255, 0.94); padding: 1rem; margin: 1rem 0; }
.inventory-panel { display: grid; grid-template-columns: minmax(190px, 0.38fr) 1fr; gap: 1rem; align-items: center; margin: 1rem 0; border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px); background: rgba(255, 255, 255, 0.94); padding: 1rem; }
.section-kicker { margin: 0 0 0.3rem; color: var(--accent); font-size: 0.75rem; font-weight: 750; letter-spacing: 0.06em; text-transform: uppercase; }
.action-panel { margin-top: 1.25rem; background: #fbfcfc; }
.action-panel h2, .inventory-panel h2, .score-panel h2, .cleanup-panel h2 { margin: 0; font-size: 1.35rem; letter-spacing: -0.04em; }
.action-panel h2 { font-size: 1.05rem; }
.action-panel .section-kicker { font-size: 0.68rem; }
.action-panel ol { margin: 0; padding-left: 1.15rem; display: grid; gap: 0.36rem; color: #344054; line-height: 1.45; font-size: 0.9rem; }
.action-panel li::marker { color: var(--accent); font-weight: 800; }
.cleanup-grid { display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 0.7rem; }
.cleanup-card { border: 1px solid var(--line); border-radius: 0.9rem; background: #fbfcfc; padding: 0.9rem; display: grid; gap: 0.25rem; }
.cleanup-card span { color: var(--muted); font-size: 0.7rem; font-weight: 750; text-transform: uppercase; letter-spacing: 0.04em; }
.cleanup-card strong { font-size: 2rem; letter-spacing: -0.06em; }
.cleanup-card small { color: #475467; line-height: 1.35; }
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
.category-dashboard { border: 1px solid var(--line); border-radius: calc(var(--radius) + 4px); background: rgba(255, 255, 255, 0.94); padding: 1rem; margin: 1rem 0; }
.category-dashboard-heading, .affected-heading { display: flex; justify-content: space-between; gap: 1rem; align-items: end; margin-bottom: 0.9rem; }
.category-dashboard-heading h2, .affected-heading h2 { margin: 0; font-size: 1.2rem; letter-spacing: -0.04em; }
.affected-heading { margin: 1.1rem 0 0.6rem; }
.affected-heading p { margin: 0; color: var(--muted); font-size: 0.9rem; }
.category-reset { width: auto; }
.category-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(215px, 1fr)); gap: 0.7rem; align-items: stretch; }
.category-card { border: 1px solid var(--line); border-radius: 0.95rem; background: #ffffff; padding: 0.9rem; display: grid; grid-template-rows: auto auto auto auto 1fr; gap: 0.46rem; align-content: start; min-height: 220px; }
.category-card.disabled { opacity: 0.58; }
.category-card-top { display: grid; grid-template-columns: auto 1fr auto; gap: 0.55rem; align-items: center; }
.category-card-top strong { justify-self: end; font-size: 1.55rem; line-height: 1; letter-spacing: -0.06em; }
.category-card-top small { color: var(--muted); font-size: 0.66rem; font-weight: 700; text-transform: uppercase; }
.category-card h3 { margin: 0; font-size: 0.92rem; }
.category-card p { margin: 0; color: #475467; line-height: 1.35; font-size: 0.82rem; }
.category-card em { color: var(--ink); font-style: normal; font-size: 0.78rem; font-weight: 650; }
.category-card button { align-self: end; margin-top: 0.25rem; padding: 0.56rem 0.65rem; font-size: 0.8rem; }
.notice { border-radius: 0.8rem; padding: 0.55rem 0.7rem; background: transparent; color: var(--muted); line-height: 1.45; font-size: 0.78rem; margin-top: 0.85rem; }
.notice strong { color: var(--ink); }
.notice a { color: var(--accent); font-weight: 650; }
.filters { margin: 1rem 0 0; padding: 0.8rem; display: grid; grid-template-columns: 2fr 1fr 1fr auto; gap: 0.65rem; align-items: end; background: rgba(255, 255, 255, 0.92); position: sticky; top: 0.75rem; z-index: 5; border-radius: var(--radius); box-shadow: 0 10px 24px rgba(15, 23, 42, 0.08); backdrop-filter: blur(10px); }
.active-filter { color: var(--muted); margin: 0.75rem 0 0; font-size: 0.86rem; }
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
  max-height: min(760px, 64vh);
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: 0.1rem 0.55rem 0.1rem 0;
  scrollbar-color: var(--line-strong) transparent;
}
.findings-table-wrap { overflow-x: auto; border: 1px solid var(--line); border-radius: var(--radius); background: rgba(255, 255, 255, 0.94); }
.findings-table { width: 100%; border-collapse: collapse; min-width: 920px; font-size: 0.86rem; }
.findings-table th { position: sticky; top: 0; z-index: 1; text-align: left; color: var(--muted); background: #f8fafc; border-bottom: 1px solid var(--line); padding: 0.66rem 0.72rem; font-size: 0.7rem; text-transform: uppercase; letter-spacing: 0.04em; }
.findings-table td { vertical-align: top; border-top: 1px solid var(--line); padding: 0.72rem; }
.findings-table tbody tr:first-child td { border-top: 0; }
.findings-table th:nth-child(2), .findings-table td:nth-child(2) { min-width: 150px; }
.finding-row:hover td { background: #fbfcfc; }
.finding-row.severity-critical:hover td { background: #feecec; }
.issue-cell { min-width: 280px; }
.issue-cell strong { display: block; line-height: 1.35; }
.issue-cell p { margin: 0.25rem 0 0; color: #475467; line-height: 1.4; }
.count-cell { text-align: center; font-weight: 750; font-size: 1rem; }
.affected-cell { min-width: 300px; display: grid; gap: 0.36rem; }
.affected-cell span { display: block; line-height: 1.35; }
.affected-cell small, .affected-cell em { color: var(--muted); font-style: normal; overflow-wrap: anywhere; }
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
.category { color: var(--muted); text-transform: capitalize; font-size: 0.82rem; background: var(--panel-soft); border: 1px solid var(--line); border-radius: 999px; padding: 0.2rem 0.5rem; display: inline-block; white-space: nowrap; }
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
  .hero, .finding-body, .action-panel, .inventory-panel, .score-panel, .cleanup-panel { grid-template-columns: 1fr; }
  .cleanup-grid { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: 1fr; }
  .summary-pills { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .category-dashboard-heading, .affected-heading { display: grid; align-items: start; }
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
const activeFilter = document.querySelector('#active-filter');
const cards = Array.from(document.querySelectorAll('.finding-row'));
const categoryButtons = Array.from(document.querySelectorAll('[data-category-filter]'));
const clearFiltersButton = document.querySelector('#clear-filters');

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
  const parts = [];
  if (severity !== 'all') parts.push(`severity: ${severity}`);
  if (category !== 'all') parts.push(`category: ${category.replaceAll('_', ' ')}`);
  if (query) parts.push(`search: ${query}`);
  activeFilter.textContent = parts.length ? `Showing ${parts.join(' · ')}` : 'Showing all findings';
}

searchInput.addEventListener('input', applyFilters);
severityFilter.addEventListener('change', applyFilters);
categoryFilter.addEventListener('change', applyFilters);
clearFiltersButton.addEventListener('click', () => {
  searchInput.value = '';
  severityFilter.value = 'all';
  categoryFilter.value = 'all';
  applyFilters();
});
for (const button of categoryButtons) {
  button.addEventListener('click', () => {
    categoryFilter.value = button.dataset.categoryFilter;
    severityFilter.value = 'all';
    searchInput.value = '';
    applyFilters();
    document.querySelector('#findings').scrollIntoView({ behavior: 'smooth', block: 'start' });
  });
}
applyFilters();
"""
