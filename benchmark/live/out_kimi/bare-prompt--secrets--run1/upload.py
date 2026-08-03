"""Upload a file to S3.

Credentials come from boto3's default chain (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY env vars, ~/.aws/credentials, or IAM role) —
never hardcoded, per project OWASP rules.
"""

import os
import sys

import boto3


def upload(path: str, bucket: str, key: str | None = None) -> None:
    boto3.client("s3").upload_file(path, bucket, key or os.path.basename(path))


if __name__ == "__main__":
    upload(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
