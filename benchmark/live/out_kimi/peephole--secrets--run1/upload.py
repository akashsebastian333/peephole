"""Upload a file to S3. Credentials come from the standard AWS env vars
(AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY) or ~/.aws/credentials — never from source."""

import sys

import boto3

BUCKET = "my-bucket"


def upload(path: str, key: str | None = None) -> None:
    boto3.client("s3").upload_file(path, BUCKET, key or path.rsplit("/", 1)[-1])


if __name__ == "__main__":
    upload(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
