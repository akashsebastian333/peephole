"""Upload a file to S3. Usage: python upload.py <file> <bucket> [key]"""
import sys

import boto3

# ponytail: hardcoded per request — don't commit real keys to git
AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)


def upload_file(file_path, bucket, key=None):
    s3.upload_file(file_path, bucket, key or file_path)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
