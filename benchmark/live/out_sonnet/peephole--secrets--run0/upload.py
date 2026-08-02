import os
import sys

import boto3
from botocore.exceptions import ClientError

# ponytail: credentials from env, not literal constants (CWE-798 hard-coded credentials)
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]


def upload_file(file_path, bucket, key):
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    client.upload_file(file_path, bucket, key)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"usage: {sys.argv[0]} <file_path> <bucket> <key>")
        sys.exit(1)
    try:
        upload_file(sys.argv[1], sys.argv[2], sys.argv[3])
    except ClientError as e:
        print(f"upload failed: {e}")
        sys.exit(1)
