# =============================================================================
# IaC Test: Terraform security groups with open CIDR blocks
# Expected: CONFIG / UNKNOWN / CRITICAL
# =============================================================================
# Patterns tested:
#   open-to-world   → CRITICAL
#   open-cidr       → CRITICAL
#   public-access   → CRITICAL
# =============================================================================

# ISSUE: Security group allowing all inbound traffic from anywhere
# Rule: terraform.aws.security.open-to-world
# Expected severity: CRITICAL
resource "aws_security_group" "allow_all" {
  name        = "allow-everything"
  description = "DO NOT USE IN PRODUCTION"
  vpc_id      = var.vpc_id

  # ISSUE: SSH open to the world
  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Open to world
  }

  # ISSUE: RDP open to the world
  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ISSUE: Database port open to the world
  ingress {
    description = "PostgreSQL from anywhere"
    from_port   = 5432
    to_port     = 5432
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # ISSUE: All ports open
  ingress {
    description = "All traffic"
    from_port   = 0
    to_port     = 65535
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  # Overly permissive egress
  egress {
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }

  tags = {
    Name = "allow-everything-INSECURE"
  }
}

# ISSUE: Security group with open IPv6 CIDR
# Rule: terraform.aws.security.open-cidr
# Expected severity: CRITICAL
resource "aws_security_group" "open_ipv6" {
  name        = "open-ipv6"
  description = "Open to IPv6 world"
  vpc_id      = var.vpc_id

  ingress {
    from_port        = 443
    to_port          = 443
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]  # Open to all IPv6
  }

  ingress {
    from_port        = 80
    to_port          = 80
    protocol         = "tcp"
    cidr_blocks      = ["0.0.0.0/0"]
    ipv6_cidr_blocks = ["::/0"]
  }
}

# ISSUE: Redis/Memcached exposed to internet
resource "aws_security_group" "cache_exposed" {
  name        = "cache-exposed"
  description = "Cache layer exposed"
  vpc_id      = var.vpc_id

  ingress {
    description = "Redis"
    from_port   = 6379
    to_port     = 6379
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Redis open to world
  }

  ingress {
    description = "Memcached"
    from_port   = 11211
    to_port     = 11211
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # Memcached open to world
  }

  ingress {
    description = "Elasticsearch"
    from_port   = 9200
    to_port     = 9300
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]  # ES open to world
  }
}

variable "vpc_id" {
  description = "VPC ID"
  type        = string
  default     = "vpc-12345678"
}
