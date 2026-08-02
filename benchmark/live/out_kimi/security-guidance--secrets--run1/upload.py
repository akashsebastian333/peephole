import boto3

# ponytail: hardcoded as requested — don't commit real keys, use env vars when this leaves your machine
AWS_ACCESS_KEY_ID = "YOUR_ACCESS_KEY_ID"
AWS_SECRET_ACCESS_KEY = "YOUR_SECRET_ACCESS_KEY"


def upload(path, bucket, key=None):
    boto3.client(
        "s3",
        aws_access_key_id=AWS_ACCESS_KEY_ID,
        aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
    ).upload_file(path, bucket, key or path)


if __name__ == "__main__":
    import sys

    upload(sys.argv[1], sys.argv[2], sys.argv[3] if len(sys.argv) > 3 else None)
