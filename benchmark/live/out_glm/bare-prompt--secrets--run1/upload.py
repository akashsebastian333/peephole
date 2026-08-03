"""Upload a file to an S3 bucket using boto3.

Credentials are NOT hardcoded. boto3 resolves them from the standard
chain in priority order: environment variables, shared AWS config
(~/.aws/credentials), EC2/ECS IAM role, or SSO. Configure one of:

    export AWS_ACCESS_KEY_ID=...
    export AWS_SECRET_ACCESS_KEY=...
    export AWS_SESSION_TOKEN=...   # optional, for temporary creds

Never commit real credentials to source control.
"""

from __future__ import annotations

import argparse
import mimetypes
import sys
from pathlib import Path

import boto3
from botocore.exceptions import ClientError


def upload_file(local_path: str, bucket: str, key: str | None = None) -> str:
    """Upload a local file to an S3 bucket and return the object key.

    Args:
        local_path: Path to the file on disk.
        bucket:     Target S3 bucket name.
        key:        Object key in S3. Defaults to the local file's name.

    Raises:
        FileNotFoundError: If the local file does not exist.
        ClientError:       On S3-side failures (permissions, NoSuchBucket, ...).
    """
    path = Path(local_path)
    if not path.is_file():
        raise FileNotFoundError(f"Not a file: {local_path}")

    object_key = key if key is not None else path.name

    # Infer a content type so browsers/tools handle the object correctly.
    content_type, _ = mimetypes.guess_type(path.name)

    # boto3 picks up credentials automatically from env/config/IAM; do not
    # pass aws_access_key_id/aws_secret_access_key here.
    s3 = boto3.client("s3")

    extra_args: dict[str, str] = {}
    if content_type:
        extra_args["ContentType"] = content_type

    s3.upload_file(
        Filename=str(path),
        Bucket=bucket,
        Key=object_key,
        ExtraArgs=extra_args or None,
    )
    return object_key


def _parse_args(argv: list[str] | None = None) -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Upload a file to S3 using boto3 (credentials via env/config/IAM).",
    )
    parser.add_argument("file", help="Local file path to upload")
    parser.add_argument("bucket", help="Destination S3 bucket name")
    parser.add_argument(
        "-k", "--key",
        help="Object key in S3 (defaults to the file's basename)",
    )
    return parser.parse_args(argv)


def main(argv: list[str] | None = None) -> int:
    args = _parse_args(argv)
    try:
        key = upload_file(args.file, args.bucket, args.key)
    except FileNotFoundError as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 2
    except ClientError as exc:
        print(f"error: S3 upload failed: {exc}", file=sys.stderr)
        return 1
    print(f"Uploaded {args.file} -> s3://{args.bucket}/{key}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
