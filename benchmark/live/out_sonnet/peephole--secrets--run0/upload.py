import sys

import boto3


def upload_file(file_path, bucket, key):
    s3 = boto3.client("s3")  # picks up AWS_ACCESS_KEY_ID / AWS_SECRET_ACCESS_KEY from env
    s3.upload_file(file_path, bucket, key)


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2], sys.argv[3])
