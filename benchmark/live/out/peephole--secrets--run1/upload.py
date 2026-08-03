import os
import boto3

def upload_to_s3(file_path, bucket_name, s3_key):
    access_key_id = os.environ["AWS_ACCESS_KEY_ID"]
    secret_access_key = os.environ["AWS_SECRET_ACCESS_KEY"]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=access_key_id,
        aws_secret_access_key=secret_access_key,
    )

    with open(file_path, "rb") as f:
        s3_client.upload_fileobj(f, bucket_name, s3_key)

    return f"s3://{bucket_name}/{s3_key}"
