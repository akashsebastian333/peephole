import sys

import boto3

# ponytail: hardcoded per request. Placeholder values — replace before use.
# Prefer env vars / IAM role (`boto3.client("s3")` picks both up automatically).
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
AWS_REGION = "us-east-1"
S3_BUCKET = "your-bucket-name"

s3 = boto3.client(
    "s3",
    region_name=AWS_REGION,
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)


def upload_file(local_path, s3_key=None):
    s3.upload_file(local_path, S3_BUCKET, s3_key or local_path)
    print(f"uploaded {local_path} -> s3://{S3_BUCKET}/{s3_key or local_path}")


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
