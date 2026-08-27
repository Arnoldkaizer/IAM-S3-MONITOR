"""AWS IAM User and Group Management."""

import boto3
import typer
from botocore.exceptions import ClientError

from aws_monitor.errors import get_aws_error_code

iam = boto3.client("iam")


def list_users():
    """Retrieve and display all IAM users."""
    response = iam.list_users()
    if not response["Users"]:
        typer.echo("No IAM users found.")
        return
    typer.echo("IAM Users:")
    typer.echo("-" * 30)
    for user in response["Users"]:
        typer.echo(user["UserName"])


def create_user(username: str):
    """Create an IAM user."""
    try:
        iam.create_user(UserName=username)
        typer.echo(f"IAM user '{username}' created successfully.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "EntityAlreadyExists":
            typer.echo(f"❌ IAM user '{username}' already exists.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def assign_user(username: str, group_name: str):
    """Add an IAM user to an IAM group."""
    try:
        iam.add_user_to_group(UserName=username, GroupName=group_name)
        typer.echo(f"User '{username}' successfully added to group '{group_name}'.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchEntity":
            typer.echo(f"❌ IAM user '{username}' or group '{group_name}' does not exist.")
        elif error_code == "LimitExceeded":
            typer.echo("❌ IAM group membership limit exceeded.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def deassign_user(username: str, group_name: str):
    """Remove an IAM user from an IAM group."""
    try:
        iam.remove_user_from_group(UserName=username, GroupName=group_name)
        typer.echo(f"User '{username}' successfully removed from group '{group_name}'.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchEntity":
            typer.echo(f"❌ IAM user '{username}' or group '{group_name}' does not exist.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def delete_user(username: str):
    """Safely delete an IAM user and clean up dependencies."""
    try:
        # 1. Remove user from all groups
        groups_response = iam.list_groups_for_user(UserName=username)
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchEntity":
            typer.echo(f"❌ IAM user '{username}' does not exist.")
            return
        typer.echo(f"❌ AWS error: {error_code}")
        return

    for group in groups_response["Groups"]:
        group_name = group["GroupName"]
        iam.remove_user_from_group(UserName=username, GroupName=group_name)
        typer.echo(f"Removed '{username}' from group '{group_name}'.")

    # 2. Delete access keys
    keys_response = iam.list_access_keys(UserName=username)
    for key in keys_response["AccessKeyMetadata"]:
        access_key_id = key["AccessKeyId"]
        iam.delete_access_key(UserName=username, AccessKeyId=access_key_id)
        typer.echo(f"Deleted access key '{access_key_id}'.")

    # 3. Delete inline policies
    inline_response = iam.list_user_policies(UserName=username)
    for policy_name in inline_response["PolicyNames"]:
        iam.delete_user_policy(UserName=username, PolicyName=policy_name)
        typer.echo(f"Deleted inline policy '{policy_name}'.")

    # 4. Detach managed policies
    attached_response = iam.list_attached_user_policies(UserName=username)
    for policy in attached_response["AttachedPolicies"]:
        policy_arn = policy["PolicyArn"]
        iam.detach_user_policy(UserName=username, PolicyArn=policy_arn)
        typer.echo(f"Detached policy '{policy_arn}'.")

    # 5. Delete the IAM user
    iam.delete_user(UserName=username)
    typer.echo(f"IAM user '{username}' deleted successfully.")


def list_groups():
    """Retrieve and display all IAM groups."""
    try:
        paginator = iam.get_paginator("list_groups")
        groups = []
        for page in paginator.paginate():
            groups.extend(page["Groups"])
        if not groups:
            typer.echo("No IAM groups found.")
            return
        typer.echo("IAM Groups:")
        typer.echo("-" * 30)
        for group in groups:
            typer.echo(group["GroupName"])
    except ClientError as e:
        error_code = get_aws_error_code(e)
        typer.echo(f"❌ AWS error: {error_code}")


def get_group_users(group_name: str):
    """Retrieve and display all users in an IAM group."""
    try:
        paginator = iam.get_paginator("get_group")
        users = []
        for page in paginator.paginate(GroupName=group_name):
            users.extend(page["Users"])
        if not users:
            typer.echo(f"No users found in group '{group_name}'.")
            return
        typer.echo(f"Users in group '{group_name}':")
        typer.echo("-" * 30)
        for user in users:
            typer.echo(user["UserName"])
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchEntity":
            typer.echo(f"❌ IAM group '{group_name}' does not exist.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")
