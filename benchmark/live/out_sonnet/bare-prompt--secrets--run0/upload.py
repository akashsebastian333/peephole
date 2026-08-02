import sys

import boto3
from botocore.exceptions import ClientError


def upload_file(file_path, bucket, key=None):
    key = key or file_path.rsplit("/", 1)[-1]
    s3 = boto3.client("s3")  # ponytail: creds via env/~/.aws/config/IAM role, never hardcoded
    s3.upload_file(file_path, bucket, key)
    return key


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: upload.py <file_path> <bucket> [key]")
        sys.exit(1)
    try:
        uploaded_key = upload_file(*sys.argv[1:4])
        print(f"uploaded to s3://{sys.argv[2]}/{uploaded_key}")
    except ClientError as e:
        print(f"upload failed: {e}")
        sys.exit(1)
