"""Upload a file to S3.

Credentials come from boto3's default chain (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY env vars, ~/.aws/credentials, or IAM role).
"""
import sys

import boto3

BUCKET = "my-bucket"


def upload(path: str, bucket: str = BUCKET, key: str | None = None) -> None:
    boto3.client("s3").upload_file(path, bucket, key or path)


if __name__ == "__main__":
    upload(sys.argv[1])
