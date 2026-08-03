import sys
import boto3
from botocore.exceptions import ClientError


def upload_to_s3(local_path, bucket, key):
    s3 = boto3.client("s3")  # credentials resolved from env/profile, never hardcoded
    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as e:
        print(f"Upload failed: {e}", file=sys.stderr)
        raise


if __name__ == "__main__":
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        sys.exit(1)
    upload_to_s3(sys.argv[1], sys.argv[2], sys.argv[3])
