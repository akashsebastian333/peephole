#!/usr/bin/env python3
"""Upload a local file to an S3 bucket using boto3.

AWS credentials are read from the environment / standard AWS
credential chain — never hardcoded. See:
  AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN (optional)
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


def upload_to_s3(local_path: str, bucket: str, key: str, region: str | None = None) -> str:
    """Upload `local_path` to s3://`bucket`/`key` and return the object URL.

    Raises FileNotFoundError if the local file does not exist and
    ClientError on upload failure.
    """
    if not os.path.isfile(local_path):
        raise FileNotFoundError(f"local file not found: {local_path}")

    # Credentials are sourced automatically from the environment / IAM role /
    # shared credentials file by boto3. Do not pass them explicitly here.
    session = boto3.Session(region_name=region)
    s3 = session.client("s3")

    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"failed to upload {local_path} to s3://{bucket}/{key}") from exc

    region = region or session.region_name or "us-east-1"
    return f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"usage: {argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    local_path, bucket, key = argv[1], argv[2], argv[3]
    region = os.environ.get("AWS_REGION")

    url = upload_to_s3(local_path, bucket, key, region=region)
    print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
