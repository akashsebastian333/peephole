import boto3

AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY"
BUCKET_NAME = "your-bucket-name"


def upload_file(file_path: str, object_name: str | None = None) -> None:
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    )
    s3.upload_file(file_path, BUCKET_NAME, object_name or file_path)
    print(f"Uploaded {file_path} to s3://{BUCKET_NAME}")


if __name__ == "__main__":
    import sys

    upload_file(sys.argv[1], sys.argv[2] if len(sys.argv) > 2 else None)
