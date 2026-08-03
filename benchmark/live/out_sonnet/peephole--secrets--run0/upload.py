import os
import sys

import boto3

AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]


def upload_file(local_path, bucket, key):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3.upload_file(local_path, bucket, key)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3])
