import boto3
import os

def upload_to_s3(file_path, bucket, key):
    """Upload file to S3 using credentials from environment variables."""
    access_key = os.getenv('AWS_ACCESS_KEY_ID')
    secret_key = os.getenv('AWS_SECRET_ACCESS_KEY')

    if not access_key or not secret_key:
        raise ValueError("AWS_ACCESS_KEY_ID and AWS_SECRET_ACCESS_KEY must be set")

    s3 = boto3.client(
        's3',
        aws_access_key_id=access_key,
        aws_secret_access_key=secret_key
    )
    s3.upload_file(file_path, bucket, key)


if __name__ == '__main__':
    upload_to_s3('example.txt', 'my-bucket', 'path/to/key')
