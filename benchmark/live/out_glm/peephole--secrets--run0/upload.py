import sys
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = "AKIAxxxxxxxxxxxxxxxxxx"
AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_REGION = "us-east-1"


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
        print("Upload failed.", file=sys.stderr)
        raise

    print("Upload complete.")
    return True


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload.py <local_path> <bucket> [key]", file=sys.stderr)
        sys.exit(1)

    local_path = sys.argv[1]
    bucket = sys.argv[2]
    key = sys.argv[3] if len(sys.argv) > 3 else None
    upload_file(local_path, bucket, key)
