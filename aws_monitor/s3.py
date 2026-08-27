"""AWS S3 Bucket and Object Management."""

import boto3
import typer
from botocore.exceptions import ClientError

from aws_monitor.errors import get_aws_error_code

s3 = boto3.client("s3")


def list_buckets():
    """Retrieve and display all S3 buckets."""
    try:
        response = s3.list_buckets()
        buckets = response["Buckets"]
        if not buckets:
            typer.echo("No S3 buckets found.")
            return
        typer.echo("S3 Buckets:")
        typer.echo("-" * 30)
        for bucket in buckets:
            typer.echo(bucket["Name"])
    except ClientError as e:
        error_code = get_aws_error_code(e)
        typer.echo(f"❌ AWS error: {error_code}")


def list_objects(bucket_name: str):
    """Retrieve and display all objects in an S3 bucket."""
    try:
        paginator = s3.get_paginator("list_objects_v2")
        objects = []
        for page in paginator.paginate(Bucket=bucket_name):
            objects.extend(page.get("Contents", []))
        if not objects:
            typer.echo(f"No objects found in bucket '{bucket_name}'.")
            return
        typer.echo(f"Objects in bucket '{bucket_name}':")
        typer.echo("-" * 30)
        for obj in objects:
            typer.echo(obj["Key"])
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchBucket":
            typer.echo(f"❌ S3 bucket '{bucket_name}' does not exist.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def upload_object(bucket_name: str, file_path: str, object_key: str):
    """Upload a local file to an S3 bucket."""
    try:
        s3.upload_file(file_path, bucket_name, object_key)
        typer.echo(f"File '{file_path}' uploaded successfully to s3://{bucket_name}/{object_key}.")
    except FileNotFoundError:
        typer.echo(f"❌ File '{file_path}' was not found.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchBucket":
            typer.echo(f"❌ S3 bucket '{bucket_name}' does not exist.")
        elif error_code == "AccessDenied":
            typer.echo(f"❌ Access denied when uploading to bucket '{bucket_name}'.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def download_object(bucket_name: str, object_key: str, file_path: str):
    """Download an S3 object to the local filesystem."""
    try:
        s3.download_file(bucket_name, object_key, file_path)
        typer.echo(f"Object 's3://{bucket_name}/{object_key}' downloaded successfully to '{file_path}'.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "NoSuchBucket":
            typer.echo(f"❌ S3 bucket '{bucket_name}' does not exist.")
        elif error_code == "404":
            typer.echo(f"❌ Object '{object_key}' does not exist in bucket '{bucket_name}'.")
        elif error_code == "AccessDenied":
            typer.echo(f"❌ Access denied when downloading '{object_key}'.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")


def delete_object(bucket_name: str, object_key: str):
    """Safely delete an existing object from an S3 bucket."""
    try:
        # Verify that the object exists
        s3.head_object(Bucket=bucket_name, Key=object_key)
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "404":
            typer.echo(f"❌ S3 object '{object_key}' does not exist in bucket '{bucket_name}'.")
        elif error_code == "NoSuchBucket":
            typer.echo(f"❌ S3 bucket '{bucket_name}' does not exist.")
        elif error_code == "AccessDenied":
            typer.echo(f"❌ Access denied when checking '{object_key}'.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")
        return

    # Ask for confirmation
    typer.echo()
    typer.echo("⚠️  You are about to delete S3 object:")
    typer.echo()
    typer.echo(f"s3://{bucket_name}/{object_key}")
    typer.echo()
    typer.echo("This action is permanent.")
    typer.echo()

    confirmation = typer.confirm("Continue?")
    if not confirmation:
        typer.echo("Deletion cancelled.")
        return

    # Delete the object
    try:
        s3.delete_object(Bucket=bucket_name, Key=object_key)
        typer.echo(f"S3 object '{object_key}' deleted successfully.")
    except ClientError as e:
        error_code = get_aws_error_code(e)
        if error_code == "AccessDenied":
            typer.echo(f"❌ Access denied when deleting '{object_key}'.")
        else:
            typer.echo(f"❌ AWS error: {error_code}")
