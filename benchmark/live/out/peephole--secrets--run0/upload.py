import boto3
import os


def upload_file_to_s3(file_path, bucket_name, object_key):
    """Upload a file to S3"""
    aws_access_key_id = os.environ['AWS_ACCESS_KEY_ID']
    aws_secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']

    s3_client = boto3.client(
        's3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    s3_client.upload_file(file_path, bucket_name, object_key)
    print(f"File {file_path} uploaded to s3://{bucket_name}/{object_key}")


if __name__ == "__main__":
    upload_file_to_s3('example.txt', 'my-bucket', 'uploads/example.txt')
