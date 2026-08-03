import sys

import boto3

AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY"


def upload_file(file_path, bucket, key=None):
    key = key or file_path.split("/")[-1]
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    client.upload_file(file_path, bucket, key)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2])
