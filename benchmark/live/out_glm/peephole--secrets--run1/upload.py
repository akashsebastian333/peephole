import os
import sys
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def upload_file(local_path, bucket, key=None):
    """Upload a file to an S3 bucket."""
    if key is None:
        key = local_path.split("/")[-1]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )

    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as e:
        print(f"Upload failed: {e}")
        return False
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload.py <local_path> <bucket> [key]")
        sys.exit(1)

    local_path = sys.argv[1]
    bucket = sys.argv[2]
    key = sys.argv[3] if len(sys.argv) > 3 else None

    ok = upload_file(local_path, bucket, key)
    if ok:
        print(f"Uploaded {local_path} to s3://{bucket}/{key or local_path.split('/')[-1]}")
    sys.exit(0 if ok else 1)
