"""IAM Security Audit Module."""

from dataclasses import dataclass
from typing import Literal

from botocore.exceptions import ClientError
from aws_monitor.errors import get_aws_error_code

import boto3
from datetime import datetime, timezone, timedelta

iam = boto3.client("iam")


@dataclass
class AuditFinding:
    """Represents a single IAM security finding."""

    category: str
    severity: Literal["LOW", "MEDIUM", "HIGH"]
    message: str
    resource: str


def format_table(rows: list[list[str]], headers: list[str]) -> str:
    """Format data as a table with borders."""
    if not rows:
        return ""

    # Calculate column widths
    col_widths = []
    for i, header in enumerate(headers):
        max_width = len(header)
        for row in rows:
            if i < len(row):
                max_width = max(max_width, len(str(row[i])))
        col_widths.append(max_width)

    # Build table
    lines = []

    # Header row
    header_line = " | ".join(
        header.ljust(col_widths[i]) for i, header in enumerate(headers)
    )
    separator = "-+-".join("-" * width for width in col_widths)
    lines.append(header_line)
    lines.append(separator)

    # Data rows
    for row in rows:
        line = " | ".join(
            str(value).ljust(col_widths[i]) if i < len(row) else ""
            for i, value in enumerate(row)
        )
        lines.append(line)

    return "\n".join(lines)


def display_findings_by_severity(findings: list[AuditFinding]):
    """Display audit findings in a table grouped by severity."""

    if not findings:
        print()
        print("=" * 70)
        print("IAM SECURITY AUDIT")
        print("=" * 70)
        print()
        print("No security findings detected.")
        print()
        return

    # Group findings by severity
    high_findings = [f for f in findings if f.severity == "HIGH"]
    medium_findings = [f for f in findings if f.severity == "MEDIUM"]
    low_findings = [f for f in findings if f.severity == "LOW"]

    print()
    print("=" * 70)
    print("IAM SECURITY AUDIT")
    print("=" * 70)

    # HIGH severity findings
    if high_findings:
        print()
        print(f"🔴 HIGH SEVERITY ({len(high_findings)} issues)")
        print("-" * 70)
        headers = ["Category", "Resource", "Issue"]
        rows = [
            [f.category, f.resource, f.message]
            for f in high_findings
        ]
        print(format_table(rows, headers))

    # MEDIUM severity findings
    if medium_findings:
        print()
        print(f"🟡 MEDIUM SEVERITY ({len(medium_findings)} issues)")
        print("-" * 70)
        headers = ["Category", "Resource", "Issue"]
        rows = [
            [f.category, f.resource, f.message]
            for f in medium_findings
        ]
        print(format_table(rows, headers))

    # LOW severity findings
    if low_findings:
        print()
        print(f"🔵 LOW SEVERITY ({len(low_findings)} issues)")
        print("-" * 70)
        headers = ["Category", "Resource", "Issue"]
        rows = [
            [f.category, f.resource, f.message]
            for f in low_findings
        ]
        print(format_table(rows, headers))

    print()
    print("=" * 70)


def display_findings_table(findings: list[AuditFinding]):
    """Display audit findings in a single table with severity column."""

    if not findings:
        print()
        print("=" * 70)
        print("IAM SECURITY AUDIT")
        print("=" * 70)
        print()
        print("No security findings detected.")
        print()
        return

    print()
    print("=" * 70)
    print("IAM SECURITY AUDIT")
    print("=" * 70)
    print()

    # Sort findings by severity (HIGH first, then MEDIUM, then LOW)
    severity_order = {"HIGH": 0, "MEDIUM": 1, "LOW": 2}
    sorted_findings = sorted(findings, key=lambda f: severity_order[f.severity])

    headers = ["Severity", "Category", "Resource", "Issue"]
    rows = [
        [
            f.severity,
            f.category,
            f.resource,
            f.message
        ]
        for f in sorted_findings
    ]

    print(format_table(rows, headers))
    print()
    print("=" * 70)


def audit_mfa():
    """Check IAM users for MFA devices."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])
        if not users:
            return findings
        for user in users:
            username = user["UserName"]
            mfa_response = iam.list_mfa_devices(UserName=username)
            if not mfa_response["MFADevices"]:
                findings.append(
                    AuditFinding(
                        category="MFA",
                        severity="MEDIUM",
                        message="User does not have MFA enabled.",
                        resource=username
                    )
                )
        return findings
    except ClientError as e:
        get_aws_error_code(e)
        return findings


def audit_access_keys():
    """Check IAM access keys for age and status."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])
        if not users:
            return findings
        threshold = datetime.now(timezone.utc) - timedelta(days=90)
        for user in users:
            username = user["UserName"]
            response = iam.list_access_keys(UserName=username)
            for key in response["AccessKeyMetadata"]:
                create_date = key["CreateDate"]
                age = datetime.now(timezone.utc) - create_date
                if create_date < threshold:
                    findings.append(
                        AuditFinding(
                            category="ACCESS_KEYS",
                            severity="MEDIUM",
                            message=f"Access key is {age.days} days old and is {key.get('Status', 'UNKNOWN')}.",
                            resource=username
                        )
                    )
        return findings
    except ClientError as e:
        get_aws_error_code(e)
        return findings


def audit_direct_policies():
    """Check IAM users for directly attached policies."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])
        if not users:
            return findings
        for user in users:
            username = user["UserName"]
            # Check inline policies
            inline_response = iam.list_user_policies(UserName=username)
            inline_policies = inline_response["PolicyNames"]
            # Check directly attached managed policies
            attached_response = iam.list_attached_user_policies(UserName=username)
            attached_policies = attached_response["AttachedPolicies"]
            for policy_name in inline_policies:
                findings.append(
                    AuditFinding(
                        category="DIRECT_POLICY",
                        severity="MEDIUM",
                        message=f"User has directly attached inline policy '{policy_name}'.",
                        resource=username
                    )
                )
            for policy in attached_policies:
                findings.append(
                    AuditFinding(
                        category="DIRECT_POLICY",
                        severity="MEDIUM",
                        message=f"User has directly attached managed policy '{policy['PolicyName']}'.",
                        resource=f"{username} (direct policy)"
                    )
                )
        return findings
    except ClientError as e:
        get_aws_error_code(e)
        return findings


def audit_admin_access():
    """Check IAM users for AdministratorAccess."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])
        if not users:
            return findings
        for user in users:
            username = user["UserName"]
            # Check directly attached managed policies
            attached_response = iam.list_attached_user_policies(UserName=username)
            for policy in attached_response["AttachedPolicies"]:
                if policy["PolicyName"] == "AdministratorAccess":
                    findings.append(
                        AuditFinding(
                            category="ADMIN_ACCESS",
                            severity="HIGH",
                            message="User has AdministratorAccess.",
                            resource=username
                        )
                    )
            # Check inline policies
            inline_response = iam.list_user_policies(UserName=username)
            for policy_name in inline_response["PolicyNames"]:
                if policy_name == "AdministratorAccess":
                    findings.append(
                        AuditFinding(
                            category="ADMIN_ACCESS",
                            severity="HIGH",
                            message="User has AdministratorAccess through an inline policy.",
                            resource=f"{username} (inline policy)"
                        )
                    )
            # Check group membership
            groups_response = iam.list_groups_for_user(UserName=username)
            for group in groups_response["Groups"]:
                group_name = group["GroupName"]
                group_policies = iam.list_attached_group_policies(GroupName=group_name)
                for policy in group_policies["AttachedPolicies"]:
                    if policy["PolicyName"] == "AdministratorAccess":
                        findings.append(
                            AuditFinding(
                                category="ADMIN_ACCESS",
                                severity="HIGH",
                                message=f"User receives AdministratorAccess through group '{group_name}'.",
                                resource=username
                            )
                        )
        return findings
    except ClientError as e:
        get_aws_error_code(e)
        return findings


def audit_group_membership():
    """Check IAM users for group membership."""
    findings = []
    try:
        paginator = iam.get_paginator("list_users")
        users = []
        for page in paginator.paginate():
            users.extend(page["Users"])
        if not users:
            return findings
        for user in users:
            username = user["UserName"]
            response = iam.list_groups_for_user(UserName=username)
            if not response["Groups"]:
                findings.append(
                    AuditFinding(
                        category="GROUP_MEMBERSHIP",
                        severity="LOW",
                        message="User does not belong to any IAM group.",
                        resource=username
                    )
                )
        return findings
    except ClientError as e:
        get_aws_error_code(e)
        return findings


def run_iam_audit():
    """Run all IAM security checks."""
    all_findings = []
    all_findings.extend(audit_mfa())
    all_findings.extend(audit_access_keys())
    all_findings.extend(audit_direct_policies())
    all_findings.extend(audit_admin_access())
    all_findings.extend(audit_group_membership())
    return all_findings
