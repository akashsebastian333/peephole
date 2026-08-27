import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_file_to_s3(file_path, bucket_name, object_name=None):
    """Upload a file to S3 bucket."""
    if object_name is None:
        object_name = file_path.split("/")[-1]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

    try:
        s3_client.upload_file(file_path, bucket_name, object_name)
        print(f"Successfully uploaded {file_path} to s3://{bucket_name}/{object_name}")
        return True
    except ClientError as e:
        print(f"Error uploading file: {e}")
        return False

if __name__ == "__main__":
    upload_file_to_s3("example.txt", "my-bucket")
