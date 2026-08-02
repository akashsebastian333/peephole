import sys
import boto3
from botocore.exceptions import ClientError

AWS_ACCESS_KEY_ID = "AKIAXXXXXXXXXXXXXXXX"
AWS_SECRET_ACCESS_KEY = "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
AWS_REGION = "us-east-1"


def upload_file(local_path: str, bucket: str, key: str) -> str:
    """Upload a local file to an S3 bucket and return its object URL."""
    s3 = boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
        region_name=AWS_REGION,
    )
    try:
        s3.upload_file(local_path, bucket, key)
    except ClientError as exc:
        raise RuntimeError(f"Failed to upload {local_path} to s3://{bucket}/{key}") from exc
    return f"https://{bucket}.s3.{AWS_REGION}.amazonaws.com/{key}"


def main() -> None:
    if len(sys.argv) != 4:
        print(f"Usage: {sys.argv[0]} <local_file> <bucket> <s3_key>", file=sys.stderr)
        sys.exit(1)
    local_file, bucket, key = sys.argv[1:4]
    url = upload_file(local_file, bucket, key)
    print(url)


if __name__ == "__main__":
    main()
