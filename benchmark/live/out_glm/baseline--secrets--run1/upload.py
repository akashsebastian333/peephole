"""Upload a local file to an S3 bucket using boto3.

Credentials are NOT hardcoded in this file. boto3 resolves them from the
standard provider chain (env vars, shared credentials file, IAM role, etc.).
Set AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY in your environment, or use a
named profile / instance role — never commit secrets to source.
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


def upload_to_s3(local_path: str, bucket: str, key: str) -> str:
    """Upload `local_path` to s3://`bucket`/`key`. Returns the S3 object URI."""
    if not os.path.isfile(local_path):
        raise FileNotFoundError(local_path)

    # Credentials come from the environment / boto3 credential chain.
    s3 = boto3.client("s3")

    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"Failed to upload {local_path} to {bucket}/{key}") from exc

    return f"s3://{bucket}/{key}"


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"Usage: {argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    _, local_path, bucket, key = argv
    uri = upload_to_s3(local_path, bucket, key)
    print(uri)
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
