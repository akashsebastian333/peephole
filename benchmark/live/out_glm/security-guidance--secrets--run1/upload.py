"""Upload a file to S3 using boto3.

Credentials are NEVER hardcoded. They are resolved by boto3 in this order:
  1. AWS IAM role (when running on EC2/ECS/EKS)
  2. Environment variables: AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY
  3. AWS_SHARED_CREDENTIALS_FILE (default ~/.aws/credentials)

To use environment variables, export them in your shell (never commit them):
    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    export AWS_DEFAULT_REGION=us-east-1
"""

import os
import sys

import boto3
from botocore.exceptions import ClientError


def upload_file(local_path: str, bucket: str, key: str) -> str:
    """Upload `local_path` to s3://`bucket`/`key` and return the object URL."""
    if not os.path.isfile(local_path):
        raise FileNotFoundError(local_path)

    # No credentials passed here on purpose: boto3 picks them up from the
    # environment / IAM role / credentials file.
    s3 = boto3.client("s3")

    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"Failed to upload {local_path} to {bucket}/{key}") from exc

    region = s3.meta.region_name
    return f"https://{bucket}.s3.{region}.amazonaws.com/{key}"


def main() -> int:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    url = upload_file(sys.argv[1], sys.argv[2], sys.argv[3])
    print(url)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
