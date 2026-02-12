# =============================================================================
# IaC Test: Terraform S3 buckets with public access
# Expected: CONFIG / UNKNOWN / CRITICAL
# =============================================================================
# Patterns tested:
#   s3-bucket-public    → CRITICAL
#   public-bucket       → CRITICAL
#   public-access       → CRITICAL
# =============================================================================

# ISSUE: S3 bucket with public access enabled
# Rule: terraform.aws.security.s3-bucket-public
# Expected severity: CRITICAL
resource "aws_s3_bucket" "public_data" {
  bucket = "company-public-data-dump"

  tags = {
    Environment = "production"
    ManagedBy   = "terraform"
  }
}

# ISSUE: Public ACL on bucket
resource "aws_s3_bucket_acl" "public_data_acl" {
  bucket = aws_s3_bucket.public_data.id
  acl    = "public-read"  # World-readable
}

# ISSUE: No server-side encryption
# Missing: aws_s3_bucket_server_side_encryption_configuration

# ISSUE: No versioning — no recovery from accidental deletion
resource "aws_s3_bucket_versioning" "public_data_versioning" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration {
    status = "Disabled"
  }
}

# ISSUE: Public access block disabled — allows public ACLs
# Rule: terraform.aws.security.public-access
# Expected severity: CRITICAL
resource "aws_s3_bucket_public_access_block" "public_data_access" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false  # Should be true
  block_public_policy     = false  # Should be true
  ignore_public_acls      = false  # Should be true
  restrict_public_buckets = false  # Should be true
}

# ISSUE: Bucket policy allowing public read
resource "aws_s3_bucket_policy" "public_data_policy" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "PublicReadGetObject"
        Effect    = "Allow"
        Principal = "*"  # Anyone in the world
        Action    = "s3:GetObject"
        Resource  = "${aws_s3_bucket.public_data.arn}/*"
      },
    ]
  })
}

# ─────────────────────────────────────────────────────
# Second bucket: customer PII with no encryption
# ─────────────────────────────────────────────────────
resource "aws_s3_bucket" "customer_pii" {
  bucket = "company-customer-pii-backup"

  tags = {
    DataClassification = "confidential"
    Environment        = "production"
  }
}

# ISSUE: No encryption on PII bucket
# No aws_s3_bucket_server_side_encryption_configuration defined

# ISSUE: No access logging
# No aws_s3_bucket_logging defined

# ISSUE: No lifecycle rules — data retained forever
# No aws_s3_bucket_lifecycle_configuration defined
