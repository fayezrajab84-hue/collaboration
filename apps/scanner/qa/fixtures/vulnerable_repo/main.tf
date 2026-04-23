# Deliberately vulnerable Terraform — fixture for IAC scanner QA.
# Triggers multiple high-confidence Checkov rules.

resource "aws_s3_bucket" "public_data" {
  bucket = "qa-fixture-public-data"
  # Triggers CKV_AWS_19  (versioning disabled by default)
  # Triggers CKV_AWS_18  (no logging configured)
  # Triggers CKV_AWS_145 (no SSE configured)
}

resource "aws_s3_bucket_acl" "public_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"   # Triggers CKV_AWS_20 (S3 public ACL)
}

resource "aws_security_group" "wide_open" {
  name = "qa-wide-open"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # Triggers CKV_AWS_24 (SSH from world)
  }

  ingress {
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]   # Triggers CKV_AWS_25 (RDP from world)
  }
}
