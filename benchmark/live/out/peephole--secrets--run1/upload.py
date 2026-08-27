import boto3
import os
from pathlib import Path

def upload_file_to_s3(file_path, bucket_name, object_name=None):
    """Upload a file to S3."""
    if object_name is None:
        object_name = Path(file_path).name

    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.environ.get('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.environ.get('AWS_SECRET_ACCESS_KEY')
    )
    s3_client.upload_file(file_path, bucket_name, object_name)

if __name__ == '__main__':
    upload_file_to_s3('example.txt', 'my-bucket')
