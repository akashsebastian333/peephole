import os
import boto3
from botocore.exceptions import ClientError


def upload_file_to_s3(file_path, bucket_name, object_name=None):
    """Upload a file to S3 bucket."""
    if object_name is None:
        object_name = os.path.basename(file_path)

    access_key = os.environ.get('AWS_ACCESS_KEY_ID')
    secret_key = os.environ.get('AWS_SECRET_ACCESS_KEY')

    if not access_key or not secret_key:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")

    s3_client = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )

    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        return True
    except ClientError as e:
        print(f"Error uploading file: {e}")
        return False


if __name__ == '__main__':
    upload_file_to_s3('local_file.txt', 'my-bucket', 'remote_file.txt')
