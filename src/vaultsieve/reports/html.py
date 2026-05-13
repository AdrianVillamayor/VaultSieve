from __future__ import annotations

from html import escape

from vaultsieve.models import AuditReport, Finding, SEVERITY_ORDER

SEVERITY_LABELS = ("critical", "high", "medium", "low", "obsolete")


def render_html_report(
    report: AuditReport,
    *,
    favicon_href: str = "vaultsieve-icon.svg",
    wordmark_href: str = "vaultsieve-wordmark.svg",
) -> str:
    findings = sorted(report.findings, key=lambda finding: SEVERITY_ORDER[finding.severity])
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
          <img class="brand-wordmark" src="{escape(wordmark_href, quote=True)}" alt="VaultSieve">
        </div>
        <p class="eyebrow">Local security dossier</p>
        <h1>Password Vault Audit</h1>
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
        _summary_card("Credentials", str(len(report.credentials)), "Entries imported"),
        _summary_card("Findings", str(len(report.findings)), "Total issues detected"),
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
      <button type="button" id="expand-all">Expand all</button>
      <button type="button" id="collapse-all">Collapse all</button>
    </section>
    """


def _render_finding_cards(report: AuditReport, findings: list[Finding]) -> str:
    if not findings:
        return "<article class=\"empty-state\">No findings detected.</article>"

    credential_map = report.credential_map()
    cards: list[str] = []
    for index, finding in enumerate(findings, start=1):
        credential_items: list[str] = []
        search_parts = [finding.severity, finding.category, finding.explanation, finding.recommendation]
        for credential_id in finding.credential_ids:
            credential = credential_map.get(credential_id)
            if credential is None:
                continue
            urls = ", ".join(credential.urls) if credential.urls else "No URL"
            search_parts.extend([credential.id, credential.name, credential.username, urls])
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
              <details {'open' if index <= 3 else ''}>
                <summary>
                  <span class="badge">{escape(finding.severity)}</span>
                  <span class="category">{escape(finding.category.replace('_', ' '))}</span>
                  <strong>{escape(finding.explanation)}</strong>
                </summary>
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
              </details>
            </article>
            """
        )
    return "".join(cards)


def _render_styles() -> str:
    return """
:root {
  color-scheme: dark;
  --paper: #ece4d0;
  --ink: #181714;
  --wash: #d8cdb5;
  --charcoal: #201f1b;
  --panel: #f7f0dd;
  --panel-2: #e5dac1;
  --line: #3a352b;
  --muted: #6f6657;
  --critical: #b42318;
  --high: #b65c00;
  --medium: #a88600;
  --low: #246a73;
  --obsolete: #59524a;
  --accent: #0b3b3c;
  --dot: rgba(24, 23, 20, 0.24);
}
* { box-sizing: border-box; }
body {
  margin: 0;
  min-height: 100vh;
  background:
    radial-gradient(circle, var(--dot) 1.15px, transparent 1.35px),
    radial-gradient(circle, rgba(11, 59, 60, 0.10) 1px, transparent 1.25px),
    radial-gradient(circle at 80% 0%, rgba(11, 59, 60, 0.20), transparent 32rem),
    var(--paper);
  background-size: 28px 28px, 112px 112px, auto, auto;
  background-position: 0 0, 14px 14px, 0 0, 0 0;
  color: var(--ink);
  font-family: Georgia, "Times New Roman", serif;
}
.shell { width: min(1240px, calc(100% - 2rem)); margin: 0 auto; padding: 1.4rem 0 2rem; }
.hero {
  display: grid;
  grid-template-columns: minmax(0, 1fr) minmax(260px, 360px);
  gap: 1rem;
  align-items: stretch;
  border: 2px solid var(--line);
  background: var(--panel);
  box-shadow: 10px 10px 0 var(--charcoal);
  padding: 1.1rem;
  margin-bottom: 1rem;
}
.brand-lockup { display: flex; align-items: center; margin-bottom: 0.9rem; }
.brand-wordmark { width: min(420px, 72vw); max-height: 118px; object-fit: contain; object-position: left center; filter: drop-shadow(4px 4px 0 rgba(11, 59, 60, 0.16)); }
.hero h1 { font-size: clamp(1.8rem, 4.8vw, 4.7rem); line-height: 0.9; margin: 0; letter-spacing: -0.07em; text-transform: uppercase; max-width: 620px; }
.eyebrow { color: var(--accent); font-family: Orbitron, ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 800; letter-spacing: 0.22em; text-transform: uppercase; }
.muted { color: var(--muted); max-width: 44rem; font-size: 1.05rem; }
.meta-card, .summary-card, .notice, .filters, .finding-card, .empty-state {
  background: var(--panel);
  border: 2px solid var(--line);
}
.meta-card { padding: 1rem; display: grid; gap: 0.35rem; align-content: end; overflow-wrap: anywhere; background: var(--charcoal); color: var(--paper); }
.meta-card span, .summary-card span, .summary-card small { color: var(--muted); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; text-transform: uppercase; font-size: 0.72rem; letter-spacing: 0.08em; }
.meta-card span { color: #b9ad96; }
.summary-grid { display: grid; grid-template-columns: 1.3fr 1.3fr repeat(4, minmax(0, 1fr)); gap: 0; margin: 1rem 0; border: 2px solid var(--line); border-right: 0; border-bottom: 0; }
.summary-card { padding: 0.85rem; display: grid; gap: 0.1rem; border: 0; border-right: 2px solid var(--line); border-bottom: 2px solid var(--line); min-height: 116px; }
.summary-card strong { font-size: 2.55rem; line-height: 1; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.summary-card.severity-critical strong { color: var(--critical); }
.summary-card.severity-high strong { color: var(--high); }
.summary-card.severity-medium strong { color: var(--medium); }
.summary-card.severity-low strong { color: var(--low); }
.summary-card.severity-obsolete strong { color: var(--obsolete); }
.notice { padding: 0.85rem 1rem; background: var(--accent); color: var(--paper); box-shadow: 6px 6px 0 var(--line); }
.filters { margin: 1rem 0 0; padding: 0.85rem; display: grid; grid-template-columns: 2fr 1fr 1fr auto auto; gap: 0.65rem; align-items: end; background: var(--wash); position: sticky; top: 0; z-index: 5; box-shadow: 0 8px 0 rgba(24, 23, 20, 0.14); }
label { color: var(--muted); display: grid; gap: 0.3rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.74rem; text-transform: uppercase; letter-spacing: 0.08em; }
input, select, button { width: 100%; border: 2px solid var(--line); border-radius: 0; background: var(--panel); color: var(--ink); padding: 0.68rem 0.72rem; font: inherit; }
button { cursor: pointer; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-weight: 800; text-transform: uppercase; font-size: 0.75rem; }
button:hover, input:focus, select:focus { outline: 3px solid var(--accent); outline-offset: 2px; }
.toolbar-result { color: var(--muted); margin: 0.75rem 0; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.findings {
  display: grid;
  gap: 0.7rem;
  max-height: min(820px, 62vh);
  overflow-y: auto;
  overscroll-behavior: contain;
  padding: 0.15rem 0.65rem 0.15rem 0;
  scrollbar-color: var(--line) transparent;
}
.finding-card { overflow: hidden; border-left-width: 12px; background: var(--panel); }
.finding-card.severity-critical { border-left-color: var(--critical); }
.finding-card.severity-high { border-left-color: var(--high); }
.finding-card.severity-medium { border-left-color: var(--medium); }
.finding-card.severity-low { border-left-color: var(--low); }
.finding-card.severity-obsolete { border-left-color: var(--obsolete); }
details { padding: 0.2rem; }
summary { cursor: pointer; list-style: none; display: grid; grid-template-columns: auto auto 1fr; gap: 0.7rem; align-items: center; padding: 0.95rem; }
summary::-webkit-details-marker { display: none; }
.badge { padding: 0.25rem 0.55rem; font-size: 0.72rem; font-weight: 900; text-transform: uppercase; background: var(--charcoal); color: var(--paper); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.category { color: var(--muted); text-transform: capitalize; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; font-size: 0.8rem; }
.finding-body { border-top: 2px dashed var(--line); padding: 1rem; display: grid; grid-template-columns: minmax(240px, 0.8fr) 1.2fr; gap: 1.2rem; background: rgba(255,255,255,0.22); }
.finding-body h3 { margin: 0 0 0.4rem; font-size: 0.8rem; font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; text-transform: uppercase; letter-spacing: 0.1em; }
.finding-body p { margin: 0; color: var(--muted); }
.credential-list { list-style: none; padding: 0; margin: 0; display: grid; gap: 0.5rem; }
.credential-list li { background: var(--panel-2); border: 1px solid var(--line); padding: 0.65rem; display: grid; gap: 0.22rem; }
.credential-list span, .credential-list small { color: var(--muted); overflow-wrap: anywhere; }
code { color: var(--accent); font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; }
.empty-state { padding: 2rem; text-align: center; color: var(--muted); }
.is-hidden { display: none; }
@media (max-width: 900px) {
  .hero, .finding-body { grid-template-columns: 1fr; }
  .summary-grid { grid-template-columns: repeat(2, minmax(0, 1fr)); }
  .filters { grid-template-columns: 1fr; position: static; }
  .findings { max-height: none; overflow: visible; padding-right: 0; }
  summary { grid-template-columns: 1fr; }
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
document.querySelector('#expand-all').addEventListener('click', () => {
  for (const detail of document.querySelectorAll('.finding-card:not(.is-hidden) details')) detail.open = true;
});
document.querySelector('#collapse-all').addEventListener('click', () => {
  for (const detail of document.querySelectorAll('.finding-card details')) detail.open = false;
});
applyFilters();
"""
