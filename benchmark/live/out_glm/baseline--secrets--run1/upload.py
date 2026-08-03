#!/usr/bin/env python3
"""Upload a file to S3 using boto3.

Credentials are NOT hardcoded here. boto3 resolves them through its
standard chain (env vars, ~/.aws/credentials, IAM role, etc.), so secrets
stay out of source control.

Usage:
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
        python upload.py <bucket> <key> <local_file>
"""

import sys

import boto3
from botocore.exceptions import ClientError


def upload_file(bucket: str, key: str, local_path: str) -> None:
    s3 = boto3.client("s3")  # credentials resolved from the environment/config chain
    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"Failed to upload {local_path} to s3://{bucket}/{key}") from exc


def main() -> int:
    if len(sys.argv) != 4:
        print("usage: upload.py <bucket> <key> <local_file>", file=sys.stderr)
        return 2
    _, bucket, key, local_path = sys.argv
    upload_file(bucket, key, local_path)
    print(f"Uploaded {local_path} -> s3://{bucket}/{key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
