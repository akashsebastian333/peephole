import boto3
import os

aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

s3_client = boto3.client(
    's3',
    aws_access_key_id=aws_access_key_id,
    aws_secret_access_key=aws_secret_access_key
)

def upload_file(file_path, bucket_name, object_name=None):
    if object_name is None:
        object_name = file_path
    s3_client.upload_file(file_path, bucket_name, object_name)
