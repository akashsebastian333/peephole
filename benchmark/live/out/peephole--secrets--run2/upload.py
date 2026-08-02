import os
import boto3

access_key_id = os.environ['AWS_ACCESS_KEY_ID']
secret_access_key = os.environ['AWS_SECRET_ACCESS_KEY']

s3_client = boto3.client(
    's3',
    aws_access_key_id=access_key_id,
    aws_secret_access_key=secret_access_key
)

def upload_file(file_path, bucket_name, object_name=None):
    if object_name is None:
        object_name = os.path.basename(file_path)

    s3_client.upload_file(file_path, bucket_name, object_name)
    print(f"Uploaded {file_path} to s3://{bucket_name}/{object_name}")

if __name__ == "__main__":
    upload_file("example.txt", "my-bucket", "uploaded-file.txt")
