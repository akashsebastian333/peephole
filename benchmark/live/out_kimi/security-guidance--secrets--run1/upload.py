import boto3

AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)


def upload(path, bucket, key=None):
    s3.upload_file(path, bucket, key or path)


if __name__ == "__main__":
    import sys

    upload(sys.argv[1], sys.argv[2], *sys.argv[3:])
