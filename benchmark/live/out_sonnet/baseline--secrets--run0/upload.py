import sys

import boto3


def upload(local_path, bucket, key):
    boto3.client("s3").upload_file(local_path, bucket, key)


if __name__ == "__main__":
    upload(sys.argv[1], sys.argv[2], sys.argv[3])
