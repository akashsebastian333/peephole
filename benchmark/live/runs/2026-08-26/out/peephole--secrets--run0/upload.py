import os
import boto3

def upload_to_s3(file_path, bucket_name, object_name):
    """Upload a file to S3."""
    s3_client = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    )
    s3_client.upload_file(file_path, bucket_name, object_name)
    print(f"Uploaded {file_path} to s3://{bucket_name}/{object_name}")

if __name__ == "__main__":
    upload_to_s3("test.txt", "my-bucket", "test.txt")
