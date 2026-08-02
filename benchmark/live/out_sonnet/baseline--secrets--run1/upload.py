import sys

import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def upload_file(file_path, bucket, key):
    client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    client.upload_file(file_path, bucket, key)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3])
