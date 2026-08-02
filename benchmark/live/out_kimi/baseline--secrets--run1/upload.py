#!/usr/bin/env python3
"""Upload a file to S3. Credentials come from env vars or ~/.aws/credentials."""
import sys

import boto3


def upload(bucket, path, key=None):
    boto3.client("s3").upload_file(path, bucket, key or path.split("/")[-1])
    print(f"uploaded {path} -> s3://{bucket}/{key or path.split('/')[-1]}")


if __name__ == "__main__":
    upload(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
