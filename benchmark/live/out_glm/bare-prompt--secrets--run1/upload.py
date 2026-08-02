"""Upload a local file to an S3 bucket using boto3.

Credentials are NOT hardcoded. boto3 resolves them through its default
credential chain: env vars (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY),
shared credentials file (~/.aws/credentials), or the attached IAM role.
"""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def upload_to_s3(local_path: Path, bucket: str, key: str) -> str:
    """Upload local_path to s3://bucket/key and return the object URI."""
    if not local_path.is_file():
        raise FileNotFoundError(f"Not a file: {local_path}")

    # Credentials are picked up from the environment / IAM role / AWS config.
    s3 = boto3.client("s3")
    s3.upload_file(str(local_path), bucket, key)
    return f"s3://{bucket}/{key}"


def main() -> int:
    parser = argparse.ArgumentParser(description="Upload a file to S3.")
    parser.add_argument("file", help="Path to the local file to upload")
    parser.add_argument("bucket", help="Destination S3 bucket name")
    parser.add_argument(
        "key",
        nargs="?",
        default=None,
        help="Object key in S3 (defaults to the local file's name)",
    )
    args = parser.parse_args()

    local_path = Path(args.file)
    key = args.key or local_path.name

    try:
        uri = upload_to_s3(local_path, args.bucket, key)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except (BotoCoreError, ClientError) as exc:
        print(f"error: upload failed: {exc}", file=sys.stderr)
        return 1

    print(uri)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
