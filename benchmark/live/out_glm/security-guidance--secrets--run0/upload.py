import sys
import boto3
from botocore.exceptions import ClientError

# NOTE: Hardcoding credentials is insecure. Prefer environment variables,
# IAM instance profiles, or AWS config files. These placeholders must be
# replaced and this file must never be committed to version control.
AWS_ACCESS_KEY_ID = "AKIAEXAMPLEACCESSKEY"
AWS_SECRET_ACCESS_KEY = "examplesecretkeyreplacewithrealvalue"
AWS_REGION = "us-east-1"


def upload_to_s3(local_path: str, bucket: str, key: str) -> str:
    """Upload a local file to an S3 bucket and return the object URL."""
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
        print(f"Usage: {sys.argv[0]} <local_path> <bucket> <key>", file=sys.stderr)
        sys.exit(1)
    url = upload_to_s3(sys.argv[1], sys.argv[2], sys.argv[3])
    print(url)


if __name__ == "__main__":
    main()
