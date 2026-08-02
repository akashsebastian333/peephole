import os
import boto3
from pathlib import Path

def upload_to_s3(file_path, bucket_name, object_name):
    path = Path(file_path).resolve()
    if not path.is_file():
        raise FileNotFoundError(f"File not found or not a file: {file_path}")

    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    s3_client.upload_file(str(path), bucket_name, object_name)
