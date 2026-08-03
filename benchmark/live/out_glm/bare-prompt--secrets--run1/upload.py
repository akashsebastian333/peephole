"""Upload a file to S3 using boto3.

Credentials are NOT stored here. boto3 resolves them automatically from, in
order: the calling process environment (AWS_ACCESS_KEY_ID /
AWS_SECRET_ACCESS_KEY), shared credentials/config files, or the attached IAM
role (EC2/ECS/EKS). Never hardcode secrets in source.

Usage:
    AWS_ACCESS_KEY_ID=... AWS_SECRET_ACCESS_KEY=... \
        python upload.py <local_path> <bucket> <key>
"""

import sys
from pathlib import Path

import boto3
from botocore.exceptions import BotoCoreError, ClientError


def upload_to_s3(local_path: Path, bucket: str, key: str) -> None:
    if not local_path.is_file():
        raise FileNotFoundError(f"Not a file: {local_path}")

    # Credentials are picked up from env / IAM role by boto3 — never hardcoded.
    s3 = boto3.client("s3")
    try:
        s3.upload_file(str(local_path), bucket, key)
    except (BotoCoreError, ClientError) as err:
        raise RuntimeError(f"Failed to upload {local_path} to s3://{bucket}/{key}: {err}") from err


def main(argv: list[str]) -> int:
    if len(argv) != 4:
        print(f"Usage: {argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    _, local_path, bucket, key = argv
    upload_to_s3(Path(local_path), bucket, key)
    print(f"Uploaded {local_path} to s3://{bucket}/{key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))
