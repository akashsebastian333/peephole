import os
import boto3

# ponytail: keys come from env, never hardcoded (AWS leak scanners flag hardcoded keys)
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")
S3_BUCKET = os.environ["S3_BUCKET"]

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    region_name=AWS_REGION,
)


def upload(path: str, key: str | None = None) -> None:
    """Upload `path` to S3 as `key` (defaults to basename)."""
    s3.upload_file(path, S3_BUCKET, key or os.path.basename(path))


if __name__ == "__main__":
    import sys

    upload(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
