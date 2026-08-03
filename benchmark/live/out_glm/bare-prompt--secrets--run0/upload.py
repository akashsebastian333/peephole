#!/usr/bin/env python3
"""Upload a local file to an S3 bucket using boto3.

Credentials are NOT hardcoded. They are resolved by boto3's standard
credential chain (env vars AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY,
shared credentials file, IAM role, etc.), which keeps secrets out of source.

Usage:
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    python upload.py <local_path> <bucket> <s3_key>
"""

import os
import sys

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def upload_file(local_path: str, bucket: str, s3_key: str) -> str:
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"Not a file: {local_path}")
    if not bucket or not s3_key:
        raise ValueError("bucket and s3_key are required")

    # Credentials come from the environment / AWS config, never from source.
    s3 = boto3.client("s3")
    try:
        s3.upload_file(local_path, bucket, s3_key)
    except (BotoCoreError, ClientError) as exc:
        raise RuntimeError(f"Upload failed: {exc}") from exc

    return f"s3://{bucket}/{s3_key}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(
            f"Usage: {argv[0]} <local_path> <bucket> <s3_key>",
            file=sys.stderr,
        )
        return 2
    try:
        url = upload_file(argv[1], argv[2], argv[3])
    except Exception as exc:  # noqa: BLE001 - top-level CLI boundary
        print(f"error: {exc}", file=sys.stderr)
        return 1
    print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
