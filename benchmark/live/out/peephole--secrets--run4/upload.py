import boto3
import os

# Credentials loaded from environment variables instead of hardcoding
AWS_ACCESS_KEY_ID = os.getenv('AWS_ACCESS_KEY_ID')
AWS_SECRET_ACCESS_KEY = os.getenv('AWS_SECRET_ACCESS_KEY')
S3_BUCKET = os.getenv('S3_BUCKET', 'default-bucket')

def upload_to_s3(file_path, s3_key):
    """Upload a file to S3."""
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )

    s3_client.upload_file(file_path, S3_BUCKET, s3_key)
    print(f"Uploaded {file_path} to s3://{S3_BUCKET}/{s3_key}")

if __name__ == '__main__':
    upload_to_s3('local_file.txt', 'remote_file.txt')
