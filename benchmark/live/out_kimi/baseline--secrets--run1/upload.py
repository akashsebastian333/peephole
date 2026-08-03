"""Upload a file to S3."""

import sys

import boto3

AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY"
AWS_REGION = "us-east-1"


def upload_file(local_path, bucket, s3_key=None):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    s3.upload_file(local_path, bucket, s3_key or local_path)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
