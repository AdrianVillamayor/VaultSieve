from __future__ import annotations

from html import escape

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
    generated_summary = _render_summary(report)
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

    <section class="notice">
      <strong>Safety note:</strong> This report contains account names, usernames, URLs, source indexes, and findings. Treat it as sensitive even though plaintext passwords are excluded.
    </section>

    {filters}

    <section class="toolbar-result">
      <span id="visible-count">{len(findings)}</span> visible findings
    </section>

    <section class="findings" id="findings">
      {finding_cards}
    </section>
  </main>
  <script>{_render_script()}</script>
</body>
</html>
"""


def _render_summary(report: AuditReport) -> str:
    cards = [
        _summary_card("Credentials", str(
            len(report.credentials)), "Entries imported"),
        _summary_card("Findings", str(len(report.findings)),
                      "Total issues detected"),
    ]
    for severity in SEVERITY_LABELS:
        cards.append(
            _summary_card(
                severity.title(),
                str(report.summary_by_severity[severity]),
                "Severity count",
                severity,
            )
        )
    return f"<section class=\"summary-grid\">{''.join(cards)}</section>"


def _summary_card(title: str, value: str, subtitle: str, severity: str | None = None) -> str:
    severity_class = f" severity-{severity}" if severity else ""
    return (
        f"<article class=\"summary-card{severity_class}\">"
        f"<span>{escape(title)}</span>"
        f"<strong>{escape(value)}</strong>"
        f"<small>{escape(subtitle)}</small>"
        "</article>"
    )


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
.notice { border-radius: var(--radius); padding: 0.82rem 1rem; background: #f8fafc; color: #475467; line-height: 1.55; }
.notice strong { color: var(--ink); }
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
  .hero, .finding-body { grid-template-columns: 1fr; }
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
