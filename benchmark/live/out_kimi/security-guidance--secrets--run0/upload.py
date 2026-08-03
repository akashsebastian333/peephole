"""Upload a file to S3.

Credentials come from boto3's default chain — NEVER hardcode keys here:
  1. Environment variables: AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY
  2. ~/.aws/credentials (via `aws configure`)
  3. IAM instance/task role (best for anything deployed)
"""

import sys

import boto3

BUCKET = "my-bucket"


def upload(local_path: str, bucket: str = BUCKET, key: str | None = None) -> None:
    boto3.client("s3").upload_file(local_path, bucket, key or local_path)


if __name__ == "__main__":
    upload(sys.argv[1], *(sys.argv[2:3] + sys.argv[3:4]))
