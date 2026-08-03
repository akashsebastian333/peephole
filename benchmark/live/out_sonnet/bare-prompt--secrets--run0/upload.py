import sys

import boto3


def upload_file(file_path, bucket, key=None):
    key = key or file_path.split("/")[-1]
    boto3.client("s3").upload_file(file_path, bucket, key)


if __name__ == "__main__":
    if len(sys.argv) not in (3, 4):
        print("usage: upload.py <file_path> <bucket> [key]", file=sys.stderr)
        sys.exit(1)
    upload_file(*sys.argv[1:])
