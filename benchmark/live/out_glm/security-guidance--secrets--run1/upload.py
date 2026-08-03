#!/usr/bin/env python3
"""Upload a file to S3 using boto3.

Credentials are read from the environment, never hardcoded:
  AWS_ACCESS_KEY_ID
  AWS_SECRET_ACCESS_KEY
  AWS_REGION (optional; boto3 falls back to its default chain)

Usage:
  AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... python upload.py <bucket> <key> <local_path>
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


def upload_to_s3(bucket: str, key: str, local_path: str) -> None:
    s3 = boto3.client(
        "s3",
        aws_access_key_id=os.environ.get("AWS_ACCESS_KEY_ID"),
        aws_secret_access_key=os.environ.get("AWS_SECRET_ACCESS_KEY"),
        region_name=os.environ.get("AWS_REGION"),
    )
    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as e:
        print(f"Upload failed: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <bucket> <key> <local_path>", file=sys.stderr)
        sys.exit(1)

    _bucket, _key, _path = sys.argv[1:4]
    if not os.environ.get("AWS_ACCESS_KEY_ID") or not os.environ.get("AWS_SECRET_ACCESS_KEY"):
        print("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set in the environment.", file=sys.stderr)
        sys.exit(1)

    upload_to_s3(_bucket, _key, _path)
    print(f"Uploaded {_path} to s3://{_bucket}/{_key}")
