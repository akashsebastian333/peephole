#!/usr/bin/env python3
"""Upload a local file to an S3 bucket using boto3.

Credentials are read from the environment (AWS_ACCESS_KEY_ID,
AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN) or the standard AWS
shared-credentials/config chain. Do not hardcode secrets in this file.
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


def upload_to_s3(local_path: str, bucket: str, key: str) -> str:
    """Upload `local_path` to s3://`bucket`/`key`. Returns the object URL."""
    if not os.path.isfile(local_path):
        raise FileNotFoundError(local_path)

    # Credentials are picked up automatically from the environment /
    # AWS config. Passing them explicitly is not required.
    s3 = boto3.client("s3")

    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"Failed to upload {local_path} to {bucket}/{key}") from exc

    region = s3.meta.region_name
    return f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"Usage: {argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    local_path, bucket, key = argv[1:]
    url = upload_to_s3(local_path, bucket, key)
    print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
