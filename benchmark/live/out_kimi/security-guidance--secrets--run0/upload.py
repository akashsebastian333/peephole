import sys

import boto3

# ponytail: hardcoded credentials per request — placeholders, replace before use.
# Better: IAM role/instance profile or env vars; hardcoding keys risks leaks.
AWS_ACCESS_KEY_ID = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_ACCESS_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"
BUCKET = "my-bucket"

s3 = boto3.client(
    "s3",
    aws_access_key_id=AWS_ACCESS_KEY_ID,
    aws_secret_access_key=AWS_SECRET_ACCESS_KEY,
)

if __name__ == "__main__":
    local_path, key = sys.argv[1], sys.argv[2]
    s3.upload_file(local_path, BUCKET, key)
