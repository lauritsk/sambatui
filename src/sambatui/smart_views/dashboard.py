from __future__ import annotations

from collections import Counter
from collections.abc import Sequence


from .models import SmartViewCheckResult, SmartViewRow


SEVERITY_ORDER = {"error": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


def full_health_dashboard_rows(
    results: Sequence[SmartViewCheckResult],
) -> list[SmartViewRow]:
    details: list[tuple[SmartViewCheckResult, SmartViewRow]] = []
    summary_rows: list[SmartViewRow] = []
    failure_rows: list[SmartViewRow] = []
    total_findings = 0

    for result in results:
        if result.error:
            failure_rows.append(dashboard_failure_row(result))
            continue
        rows = list(result.rows)
        total_findings += len(rows)
        details.extend((result, row) for row in rows)
        summary_rows.append(dashboard_summary_row(result, rows))

    top_row = dashboard_total_row(total_findings, summary_rows, failure_rows)
    detail_rows = [
        dashboard_detail_row(result, row) for result, row in sorted_details(details)
    ]
    return [top_row, *summary_rows, *failure_rows, *detail_rows]


def dashboard_failure_row(result: SmartViewCheckResult) -> SmartViewRow:
    return SmartViewRow(
        severity="error",
        object=f"{result.source}:{result.label}",
        finding=f"{result.label}: Health check failed",
        evidence=result.error,
        suggested_action="Fix the connection or permissions, then rerun the dashboard.",
        source="dashboard",
    )


def dashboard_summary_row(
    result: SmartViewCheckResult, rows: Sequence[SmartViewRow]
) -> SmartViewRow:
    return SmartViewRow(
        severity="summary",
        object=result.source,
        finding=result.label,
        evidence=severity_count_text(rows),
        suggested_action="Review detailed rows below; high severity first.",
        source="dashboard",
    )


def dashboard_total_row(
    total_findings: int,
    summary_rows: Sequence[SmartViewRow],
    failure_rows: Sequence[SmartViewRow],
) -> SmartViewRow:
    return SmartViewRow(
        severity="summary",
        object="Total",
        finding="Full health dashboard",
        evidence=(
            f"{total_findings} finding(s); {len(summary_rows)} check(s) succeeded; "
            f"{len(failure_rows)} check(s) failed."
        ),
        suggested_action="Review failures first, then high and medium findings.",
        source="dashboard",
    )


def severity_count_text(rows: Sequence[SmartViewRow]) -> str:
    if not rows:
        return "0 findings"
    counts = Counter(row.severity for row in rows)
    return ", ".join(
        f"{severity}={counts[severity]}"
        for severity in sorted(counts, key=severity_rank)
    )


def sorted_details(
    details: Sequence[tuple[SmartViewCheckResult, SmartViewRow]],
) -> list[tuple[SmartViewCheckResult, SmartViewRow]]:
    return sorted(
        details,
        key=lambda item: (
            severity_rank(item[1].severity),
            item[1].source.casefold(),
            item[0].label.casefold(),
            item[1].object.casefold(),
            item[1].finding.casefold(),
        ),
    )


def dashboard_detail_row(
    result: SmartViewCheckResult, row: SmartViewRow
) -> SmartViewRow:
    return SmartViewRow(
        severity=row.severity,
        object=row.object,
        finding=f"{result.label}: {row.finding}",
        evidence=row.evidence,
        suggested_action=row.suggested_action,
        source=row.source,
        fix_action=row.fix_action,
        fix_label=row.fix_label,
        fix_zone=row.fix_zone,
        fix_name=row.fix_name,
        fix_rtype=row.fix_rtype,
        fix_value=row.fix_value,
    )


def severity_rank(severity: str) -> int:
    return SEVERITY_ORDER.get(severity.casefold(), 99)
