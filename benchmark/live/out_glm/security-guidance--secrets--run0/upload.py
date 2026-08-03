import os
import sys
import boto3
from botocore.exceptions import ClientError


def upload_file(local_path, bucket, key=None):
    """Upload a file to an S3 bucket.

    Credentials are NOT stored in this file. boto3 resolves them from the
    standard locations: environment variables (AWS_ACCESS_KEY_ID,
    AWS_SECRET_ACCESS_KEY), ~/.aws/credentials, instance/role metadata, etc.
    """
    if key is None:
        key = os.path.basename(local_path)

    s3 = boto3.client("s3")
    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as e:
        print(f"Upload failed: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload.py <local_path> <bucket> [key]", file=sys.stderr)
        sys.exit(1)
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
