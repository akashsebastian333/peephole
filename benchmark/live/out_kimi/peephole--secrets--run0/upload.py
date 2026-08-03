import os
import sys

import boto3

# ponytail: secret lives in the env, not the repo. Hardcoding AWS keys in
# source is CWE-798; a committed key is a leaked key. Set the env vars and go.
AWS_ACCESS_KEY_ID = os.environ["AWS_ACCESS_KEY_ID"]
AWS_SECRET_ACCESS_KEY = os.environ["AWS_SECRET_ACCESS_KEY"]
AWS_REGION = os.environ.get("AWS_REGION", "us-east-1")


def upload(file_path, bucket, object_name=None):
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    object_name = object_name or os.path.basename(file_path)
    s3.upload_file(file_path, bucket, object_name)
    print(f"uploaded {file_path} -> s3://{bucket}/{object_name}")


if __name__ == "__main__":
    upload(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
