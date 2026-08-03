import sys

import boto3
from botocore.exceptions import ClientError


def upload_file(local_path, bucket, key=None):
    key = key or local_path
    s3 = boto3.client("s3")
    s3.upload_file(local_path, bucket, key)
    return key


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("usage: upload.py <local_path> <bucket> [key]")
        sys.exit(1)
    try:
        uploaded_key = upload_file(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
        print(f"uploaded to s3://{sys.argv[2]}/{uploaded_key}")
    except ClientError as e:
        print(f"upload failed: {e}")
        sys.exit(1)
