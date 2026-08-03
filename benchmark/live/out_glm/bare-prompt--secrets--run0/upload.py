"""Upload a local file to an S3 bucket using boto3.

Credentials are NOT hardcoded. They are resolved through boto3's default
credential chain (AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY env vars,
~/.aws/credentials, instance/role metadata, etc.).
"""

from __future__ import annotations

import argparse
import mimetypes
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def upload_file(bucket: str, key: str, source: Path, region: str | None = None) -> str:
    """Upload `source` to s3://bucket/key. Returns the object URI."""
    if not source.is_file():
        raise FileNotFoundError(f"not a file: {source}")

    # Extra safety net so a path traversal-ish key never escapes the prefix.
    key = key.lstrip("/")

    session = boto3.session.Session(region_name=region)
    client = session.client("s3")

    content_type, _ = mimetypes.guess_type(source.name)
    extra_args: dict[str, str] = {}
    if content_type:
        extra_args["ContentType"] = content_type

    try:
        client.upload_file(
            str(source),
            bucket,
            key,
            ExtraArgs=extra_args or None,
        )
    except ClientError as exc:
        raise RuntimeError(f"upload failed: {exc}") from exc

    return f"s3://{bucket}/{key}"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Upload a file to S3.")
    parser.add_argument("bucket", help="target S3 bucket name")
    parser.add_argument("key", help="destination object key in the bucket")
    parser.add_argument("file", help="local path to the file to upload")
    parser.add_argument("--region", help="AWS region (optional)")
    args = parser.parse_args(argv)

    uri = upload_file(args.bucket, args.key, Path(args.file), region=args.region)
    print(uri)
    return 0


if __name__ == "__main__":
    sys.exit(main())
