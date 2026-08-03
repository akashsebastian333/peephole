import sys
import boto3


def upload(local_path, bucket, key):
    boto3.client("s3").upload_file(local_path, bucket, key)


if __name__ == "__main__":
    if len(sys.argv) != 4:
        sys.exit(f"usage: {sys.argv[0]} <local_path> <bucket> <key>")
    upload(*sys.argv[1:4])
