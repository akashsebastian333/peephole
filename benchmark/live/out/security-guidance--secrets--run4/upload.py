import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

def upload_file_to_s3(file_path, bucket_name, object_name):
    s3_client = boto3.client(
        's3',
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY
    )

    s3_client.upload_file(file_path, bucket_name, object_name)

if __name__ == "__main__":
    upload_file_to_s3("example.txt", "my-bucket", "example.txt")
