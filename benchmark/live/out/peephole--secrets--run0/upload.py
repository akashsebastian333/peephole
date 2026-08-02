import boto3
import os

def upload_to_s3(file_path, bucket_name, s3_key):
    aws_access_key_id = os.getenv('AWS_ACCESS_KEY_ID')
    aws_secret_access_key = os.getenv('AWS_SECRET_ACCESS_KEY')

    if not aws_access_key_id or not aws_secret_access_key:
        raise ValueError("AWS credentials not found in environment variables")

    s3_client = boto3.client(
        's3',
        aws_access_key_id=aws_access_key_id,
        aws_secret_access_key=aws_secret_access_key
    )

    s3_client.upload_file(file_path, bucket_name, s3_key)
    print(f"File {file_path} uploaded to s3://{bucket_name}/{s3_key}")

if __name__ == "__main__":
    import sys
    if len(sys.argv) < 4:
        print("Usage: python upload.py <file_path> <bucket_name> <s3_key>")
        sys.exit(1)

    upload_to_s3(sys.argv[1], sys.argv[2], sys.argv[3])
