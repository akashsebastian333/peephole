"""Upload a file to S3. Credentials come from the environment / IAM role —
never hardcoded (see CLAUDE.md). Set AWS_ACCESS_KEY_ID and
AWS_SECRET_ACCESS_KEY (or AWS_PROFILE / an instance role) before running."""

import sys

import boto3

BUCKET = "my-bucket"


def upload(local_path: str, bucket: str = BUCKET, key: str | None = None) -> None:
    boto3.client("s3").upload_file(local_path, bucket, key or local_path)


if __name__ == "__main__":
    upload(sys.argv[1], *(sys.argv[2:] or []))
