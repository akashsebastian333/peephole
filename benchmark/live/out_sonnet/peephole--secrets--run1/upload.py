import sys

import boto3


def upload_file(file_path, bucket, key=None):
    s3 = boto3.client("s3")
    s3.upload_file(file_path, bucket, key or file_path.split("/")[-1])


if __name__ == "__main__":
    upload_file(sys.argv[1], sys.argv[2])
