import os
import boto3
from botocore.exceptions import ClientError


def upload_to_s3(file_path: str, bucket: str, key: str) -> bool:
    """Upload a file to S3."""
    aws_access_key_id = os.environ.get("AWS_ACCESS_KEY_ID")
    aws_secret_access_key = os.environ.get("AWS_SECRET_ACCESS_KEY")
    region = os.environ.get("AWS_REGION", "us-east-1")

    if not aws_access_key_id or not aws_secret_access_key:
        raise ValueError("AWS credentials not found in environment variables")

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key,
        region_name=region,
    )

    try:
        s3_client.upload_file(file_path, bucket, key)
        return True
    except ClientError as e:
        print(f"Error uploading file: {e}")
        return False
