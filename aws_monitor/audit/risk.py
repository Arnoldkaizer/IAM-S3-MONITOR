"""IAM Risk Calculation Module."""

from dataclasses import dataclass

from aws_monitor.audit.iam import AuditFinding

SEVERITY_WEIGHTS = {
    "LOW": 1,
    "MEDIUM": 3,
    "HIGH": 6,
}


@dataclass
class RiskResult:
    """Represents the calculated IAM risk."""

    score: float
    level: str
    findings: list[AuditFinding]


def deduplicate_findings(findings: list[AuditFinding]) -> list[AuditFinding]:
    """Remove duplicate findings for risk scoring."""
    unique_findings = []
    seen = set()
    for finding in findings:
        key = (finding.category, finding.resource)
        if key in seen:
            continue
        seen.add(key)
        unique_findings.append(finding)
    return unique_findings


def calculate_risk(findings: list[AuditFinding]) -> RiskResult:
    """Calculate IAM risk score and level."""
    unique_findings = deduplicate_findings(findings)
    if not unique_findings:
        return RiskResult(score=0.0, level="LOW", findings=[])
    total_weight = sum(SEVERITY_WEIGHTS[finding.severity] for finding in unique_findings)
    max_weight = len(unique_findings) * SEVERITY_WEIGHTS["HIGH"]
    score = (total_weight / max_weight) * 10
    score = round(score, 1)
    if score >= 7:
        level = "HIGH"
    elif score >= 4:
        level = "MEDIUM"
    else:
        level = "LOW"
    return RiskResult(score=score, level=level, findings=unique_findings)


def display_risk_result(result: RiskResult):
    """Display IAM risk assessment."""
    print()
    print("=" * 50)
    print("IAM RISK ASSESSMENT")
    print("=" * 50)
    print()
    print(f"Risk Score: {result.score} / 10")
    print(f"Risk Level: {result.level}")
    print()
    if not result.findings:
        print("No security findings detected.")
        return
    print(f"Findings considered: {len(result.findings)}")
    print()
    for finding in result.findings:
        print(f"[{finding.severity}] {finding.category}")
        print(f"  Resource: {finding.resource}")
        print(f"  {finding.message}")
        print()
