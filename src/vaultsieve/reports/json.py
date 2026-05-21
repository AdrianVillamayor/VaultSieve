from __future__ import annotations

import json

from vaultsieve.models import AuditReport


def render_json_report(report: AuditReport) -> str:
    return json.dumps(report.to_safe_dict(), ensure_ascii=False, indent=2)
