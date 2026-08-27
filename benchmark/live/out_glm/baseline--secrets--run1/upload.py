import sys
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = "AKIAxxxxxxxxxxxxxxxxx"
AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_REGION = "us-east-1"
BUCKET_NAME = "my-bucket-name"


def upload_file(file_path, object_name=None):
    """Upload a file to an S3 bucket.

    :param file_path: Path to the file to upload.
    :param object_name: S3 object name. If not specified, file_path's basename is used.
    :return: True if upload succeeded, False otherwise.
    """
    if object_name is None:
        object_name = file_path.rsplit("/", 1)[-1]

    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )

    try:
        s3.upload_file(file_path, BUCKET_NAME, object_name)
    except ClientError as e:
        print(f"Upload failed: {e}", file=sys.stderr)
        return False
    return True


if __name__ == "__main__":
    if len(sys.argv) < 2:
        print("Usage: python upload.py <file_path> [object_name]", file=sys.stderr)
        sys.exit(1)

    file_path = sys.argv[1]
    object_name = sys.argv[2] if len(sys.argv) > 2 else None

    if upload_file(file_path, object_name):
        print(f"Uploaded {file_path} to s3://{BUCKET_NAME}/{object_name}")
    else:
        sys.exit(1)
