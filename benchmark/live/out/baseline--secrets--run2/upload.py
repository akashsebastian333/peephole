import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_file(file_path, bucket_name, object_name=None):
    if object_name is None:
        object_name = file_path.split("/")[-1]

    s3_client = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )

    s3_client.upload_file(file_path, bucket_name, object_name)
    return f"s3://{bucket_name}/{object_name}"
