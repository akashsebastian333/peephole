import sys
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = "AKIAXXXXXXXXXXXXXXXX"
AWS_SECRET_ACCESS_KEY = "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX"
AWS_REGION = "us-east-1"


def upload_to_s3(file_path, bucket, key=None):
    if key is None:
        key = file_path.split("/")[-1]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )

    try:
        s3.upload_file(file_path, bucket, key)
    except ClientError as e:
        print(f"Upload failed: {e}", file=sys.stderr)
        raise

    print(f"Uploaded {file_path} to s3://{bucket}/{key}")


if __name__ == "__main__":
    if len(sys.argv) < 3:
        print("Usage: python upload.py <file_path> <bucket> [key]", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    bucket = sys.argv[2]
    key = sys.argv[3] if len(sys.argv) > 3 else None

    upload_to_s3(file_path, bucket, key)
