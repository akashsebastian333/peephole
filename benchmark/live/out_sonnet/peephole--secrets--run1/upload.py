import os
import sys

import boto3

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]


def upload_file(file_path, bucket, key=None):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3.upload_file(file_path, bucket, key or os.path.basename(file_path))


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2])
