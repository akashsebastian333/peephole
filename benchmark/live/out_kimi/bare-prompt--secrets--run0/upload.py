"""Upload a file to S3.

Credentials come from the standard boto3 chain (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY env vars, ~/.aws/credentials, IAM role) — never
hardcoded.
"""

import sys
import boto3

BUCKET = "my-bucket"


def upload(file_path: str, key: str | None = None, bucket: str = BUCKET) -> None:
    s3 = boto3.client("s3")
    s3.upload_file(file_path, bucket, key or file_path)


if __name__ == "__main__":
    if len(sys.argv) < 2:
        sys.exit("usage: python upload.py <file> [s3-key]")
    upload(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
