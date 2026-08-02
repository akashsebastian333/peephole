import os
import sys
import boto3
from botocore.exceptions import ClientError


def upload_to_s3(local_path: str, bucket: str, key: str) -> str:
    """Upload a file to S3 and return the object URI.

    Credentials are resolved by boto3's standard chain (environment
    variables, shared credentials file, IAM role, etc.) — never hardcoded.
    """
    if not os.path.isfile(local_path):
        raise FileNotFoundError(local_path)

    # Let boto3 pick up AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from the
    # environment, or any other source in its default credential chain.
    s3 = boto3.client("s3")
    s3.upload_file(local_path, bucket, key)
    return f"s3://{bucket}/{key}"


def main() -> int:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        return 2

    local_path, bucket, key = sys.argv[1:4]
    try:
        uri = upload_to_s3(local_path, bucket, key)
    except ClientError as exc:
        print(f"Upload failed: {exc}", file=sys.stderr)
        return 1

    print(f"Uploaded to {uri}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
