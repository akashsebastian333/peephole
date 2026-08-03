"""Upload a file to S3. Credentials come from the standard boto3 chain
(env vars AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY, ~/.aws/credentials, or IAM role)."""

import sys

import boto3

BUCKET = "my-bucket"


def upload(path: str, key: str | None = None, bucket: str = BUCKET) -> None:
    boto3.client("s3").upload_file(path, bucket, key or path.rsplit("/", 1)[-1])


if __name__ == "__main__":
    upload(*sys.argv[1:])
