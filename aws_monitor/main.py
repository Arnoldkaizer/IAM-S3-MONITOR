#!/usr/bin/env python3
"""AWS IAM and S3 Monitor CLI."""

import typer

from aws_monitor.iam import (
    list_users,
    create_user,
    assign_user,
    deassign_user,
    delete_user,
    list_groups,
    get_group_users,
)

from aws_monitor.s3 import (
    list_buckets,
    list_objects,
    upload_object,
    download_object,
    delete_object,
)

from aws_monitor.audit import (
    audit_mfa,
    audit_access_keys,
    audit_direct_policies,
    audit_admin_access,
    audit_group_membership,
    run_iam_audit,
    calculate_risk,
    display_risk_result,
    display_findings_by_severity,
)

from aws_monitor.scanning import S3MalwareScanner

app = typer.Typer(
    name="aws-monitor",
    help="AWS IAM and S3 Monitoring CLI"
)

iam_app = typer.Typer(help="Manage AWS IAM resources")
groups_app = typer.Typer(help="Manage IAM groups")
users_app = typer.Typer(help="Manage IAM users")
s3_app = typer.Typer(help="Manage AWS S3 resources")
audit_app = typer.Typer(help="Run AWS security audits")


# Build the app structure
app.add_typer(iam_app, name="iam")
app.add_typer(s3_app, name="s3")
app.add_typer(audit_app, name="audit")
iam_app.add_typer(groups_app, name="groups")
iam_app.add_typer(users_app, name="users")


@app.callback()
def main():
    """AWS IAM and S3 Monitoring CLI."""
    pass


# ==================== IAM Users ====================
@users_app.command("list")
def list_iam_users():
    """List all IAM users."""
    list_users()


@users_app.command("create")
def create_iam_user(username: str = typer.Argument(..., help="IAM username")):
    """Create an IAM user."""
    create_user(username)


@users_app.command("assign")
def assign_iam_user(
    username: str = typer.Argument(..., help="IAM username"),
    group_name: str = typer.Argument(..., help="IAM group name"),
):
    """Add an IAM user to an IAM group."""
    assign_user(username, group_name)


@users_app.command("deassign")
def deassign_iam_user(
    username: str = typer.Argument(..., help="IAM username"),
    group_name: str = typer.Argument(..., help="IAM group name"),
):
    """Remove an IAM user from an IAM group."""
    deassign_user(username, group_name)


@users_app.command("delete")
def delete_iam_user(
    username: str = typer.Argument(..., help="IAM username"),
):
    """Safely delete an IAM user and clean up dependencies."""
    typer.echo(f"\nYou are about to delete IAM user: {username}\n")
    typer.echo("This action will permanently remove the user and associated IAM resources.\n")
    confirmation = typer.confirm("Continue?")
    if not confirmation:
        typer.echo("Deletion cancelled.")
        raise typer.Exit()
    delete_user(username)


# ==================== IAM Groups ====================
@groups_app.command("list")
def list_iam_groups():
    """List all IAM groups."""
    list_groups()


@groups_app.command("users")
def list_group_users_cmd(
    group_name: str = typer.Argument(..., help="IAM group name"),
):
    """List all users in an IAM group."""
    get_group_users(group_name)


# ==================== S3 Commands ====================
@s3_app.command("list")
def list_s3_buckets():
    """List all S3 buckets."""
    list_buckets()


@s3_app.command("objects")
def list_s3_objects(bucket_name: str = typer.Argument(..., help="S3 bucket name")):
    """List all objects in an S3 bucket."""
    list_objects(bucket_name)


@s3_app.command("upload")
def upload_s3_object(
    bucket_name: str = typer.Argument(..., help="S3 bucket name"),
    file_path: str = typer.Argument(..., help="Path to local file"),
    object_key: str = typer.Argument(..., help="S3 object key"),
):
    """Upload a file to an S3 bucket."""
    upload_object(bucket_name, file_path, object_key)


@s3_app.command("download")
def download_s3_object(
    bucket_name: str = typer.Argument(..., help="S3 bucket name"),
    object_key: str = typer.Argument(..., help="S3 object key"),
    file_path: str = typer.Argument(..., help="Local destination path"),
):
    """Download an S3 object."""
    download_object(bucket_name, object_key, file_path)


@s3_app.command("delete")
def delete_s3_object(
    bucket_name: str = typer.Argument(..., help="S3 bucket name"),
    object_key: str = typer.Argument(..., help="S3 object key"),
):
    """Safely delete an S3 object."""
    delete_object(bucket_name, object_key)


# ==================== S3 Scanning ====================
@s3_app.command("scan")
def scan_s3_object(
    bucket_name: str = typer.Argument(..., help="S3 bucket name"),
    object_key: str = typer.Argument(..., help="S3 object key"),
):
    """Scan an S3 object for malware, file spoofing, and dangerous content."""
    scanner = S3MalwareScanner()
    typer.echo(f"Scanning S3 object: s3://{bucket_name}/{object_key}...")
    result = scanner.scan_s3_object(bucket_name, object_key)

    typer.echo(f"  FileType   : {result.detected_file_type}")
    typer.echo(f"  Entropy    : {result.entropy}/8.0")
    typer.echo(f"  Risk Score : {result.risk_score}/10")
    typer.echo(f"  Suspicious : {'YES' if result.is_suspicious else 'NO'}")

    if result.threats:
        typer.echo("  Threats Found:")
        for t in result.threats:
            typer.echo(f"    - {t}")


@s3_app.command("scan-bucket")
def scan_s3_bucket(
    bucket_name: str = typer.Argument(..., help="S3 bucket name"),
    max_objects: int = typer.Option(50, "--max-objects", "-n", help="Max objects to scan"),
):
    """Scan all objects in an S3 bucket for security risks and malware."""
    scanner = S3MalwareScanner()
    typer.echo(f"Scanning S3 bucket s3://{bucket_name} (max {max_objects} objects)...")
    results = scanner.scan_bucket(bucket_name, max_objects=max_objects)

    suspicious_count = sum(1 for r in results if r.is_suspicious)
    typer.echo(f"\nScanned {len(results)} objects in {bucket_name}. Suspicious objects: {suspicious_count}")

    for r in results:
        if r.is_suspicious:
            typer.echo(f"  [{r.risk_score}/10] {r.object_key} - {', '.join(r.threats)}")


# ==================== IAM Audit ====================
@audit_app.command("mfa")
def audit_iam_mfa():
    """Audit IAM users for MFA."""
    findings = audit_mfa()
    if not findings:
        typer.echo("No findings detected.")
        return
    display_findings_by_severity(findings)


@audit_app.command("access-keys")
def audit_iam_access_keys():
    """Audit IAM access keys for age."""
    findings = audit_access_keys()
    if not findings:
        typer.echo("No findings detected.")
        return
    display_findings_by_severity(findings)


@audit_app.command("direct-policies")
def audit_iam_direct_policies():
    """Audit IAM users for directly attached policies."""
    findings = audit_direct_policies()
    if not findings:
        typer.echo("No findings detected.")
        return
    display_findings_by_severity(findings)


@audit_app.command("admin-access")
def audit_iam_admin_access():
    """Audit IAM users for AdministratorAccess."""
    findings = audit_admin_access()
    if not findings:
        typer.echo("No findings detected.")
        return
    display_findings_by_severity(findings)


@audit_app.command("groups")
def audit_iam_groups():
    """Audit IAM users for group membership."""
    findings = audit_group_membership()
    if not findings:
        typer.echo("No findings detected.")
        return
    display_findings_by_severity(findings)


@audit_app.command("all")
def audit_iam_all():
    """Run full IAM security audit with risk scoring."""
    all_findings = run_iam_audit()

    # Display table of all findings grouped by severity
    display_findings_by_severity(all_findings)

    # Display risk score only (without redundant findings)
    result = calculate_risk(all_findings)
    print()
    print(f"Risk Score: {result.score} / 10")
    print(f"Risk Level: {result.level}")


if __name__ == "__main__":
    app()
