import sys

import boto3


def upload_file(local_path, bucket, key):
    boto3.client("s3").upload_file(local_path, bucket, key)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit("usage: upload.py <local_path> <bucket> <key>")
    upload_file(*sys.argv[1:])
