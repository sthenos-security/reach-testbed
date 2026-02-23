resource "aws_s3_bucket" "data_lake" {
  bucket = "company-data-lake-prod"
  # Config: S3 bucket with public access — should flag
}

resource "aws_s3_bucket_acl" "data_lake_acl" {
  bucket = aws_s3_bucket.data_lake.id
  acl    = "public-read"  # Config: PUBLIC READ — should flag
}

resource "aws_s3_bucket_versioning" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id
  versioning_configuration {
    status = "Disabled"  # Config: versioning disabled
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "data_lake" {
  bucket = aws_s3_bucket.data_lake.id
  # MISSING: no encryption rule — should flag
}

resource "aws_s3_bucket" "logs" {
  bucket = "company-access-logs"
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
  # Compliant: all public access blocked — should NOT flag
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"  # Compliant
    }
  }
}

resource "aws_instance" "web" {
  ami           = "ami-0abcdef1234567890"
  instance_type = "t3.medium"

  # Config: SSH open to world — should flag
  vpc_security_group_ids = [aws_security_group.open_ssh.id]

  # Config: no IMDSv2 enforcement — metadata service attack vector
  metadata_options {
    http_endpoint = "enabled"
    http_tokens   = "optional"  # Should be "required" for IMDSv2
  }

  # Hardcoded secret in user_data — should flag
  user_data = <<-EOF
    #!/bin/bash
    export DB_PASSWORD="Pr0d_DB_P@ssw0rd_2026!"
    export API_KEY="sk_live_4eC39HqLyjWDarjtT1zdp7dc"
    /opt/app/start.sh
  EOF

  tags = {
    Name = "web-server-prod"
  }
}

resource "aws_security_group" "open_ssh" {
  name        = "open-ssh"
  description = "Allows SSH from anywhere"

  ingress {
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Config: SSH open to internet — should flag
  }

  ingress {
    from_port   = 3306
    to_port     = 3306
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Config: MySQL open to internet — should flag
  }

  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

resource "aws_db_instance" "main" {
  identifier        = "prod-database"
  engine            = "mysql"
  engine_version    = "5.7"  # Config: outdated MySQL version
  instance_class    = "db.t3.medium"
  allocated_storage = 100

  # Config: database publicly accessible — should flag
  publicly_accessible = true

  # Hardcoded credentials — should flag
  username = "admin"
  password = "Mysql_Pr0d_P@ssw0rd!"

  # Config: storage not encrypted — should flag
  storage_encrypted = false

  # Config: deletion protection disabled
  deletion_protection = false

  # Config: no automated backups
  backup_retention_period = 0

  skip_final_snapshot = true
}

resource "aws_iam_user" "service_account" {
  name = "app-service-user"
}

resource "aws_iam_user_policy" "service_account_policy" {
  name = "admin-policy"
  user = aws_iam_user.service_account.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Effect   = "Allow"
        Action   = "*"           # Config: wildcard action — should flag
        Resource = "*"           # Config: wildcard resource — should flag
      }
    ]
  })
}

resource "aws_kms_key" "data" {
  description             = "Data encryption key"
  enable_key_rotation     = false  # Config: key rotation disabled — should flag
  deletion_window_in_days = 7
}

resource "aws_cloudtrail" "main" {
  name                          = "prod-trail"
  s3_bucket_name                = aws_s3_bucket.logs.id
  include_global_service_events = false  # Config: global events not logged
  is_multi_region_trail         = false  # Config: not multi-region — should flag
  enable_log_file_validation    = false  # Config: log validation disabled
}

resource "aws_eks_cluster" "main" {
  name     = "prod-cluster"
  role_arn = aws_iam_role.eks.arn

  version = "1.24"  # Config: outdated EKS version

  vpc_config {
    endpoint_public_access  = true   # Config: public API endpoint
    endpoint_private_access = false
  }

  # Config: envelope encryption for secrets not enabled
  # (encryption_config block missing)
}

resource "aws_iam_role" "eks" {
  name = "eks-cluster-role"
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Action    = "sts:AssumeRole"
      Effect    = "Allow"
      Principal = { Service = "eks.amazonaws.com" }
    }]
  })
}
