import os
import boto3

def upload_to_s3(file_path, bucket, key):
    s3 = boto3.client(
        's3',
        aws_access_key_id=os.getenv('AWS_ACCESS_KEY_ID'),
        aws_secret_access_key=os.getenv('AWS_SECRET_ACCESS_KEY'),
    )
    s3.upload_file(file_path, bucket, key)

if __name__ == '__main__':
    upload_to_s3('example.txt', 'my-bucket', 'example.txt')
