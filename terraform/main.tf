# =====================================================================
# aws-cspm-lab: INTENTIONALLY INSECURE LAB ENVIRONMENT
#
# Every resource below contains a deliberate misconfiguration so that
# Checkov (code scanning) and Prowler (live account scanning) have real
# findings to detect, triage and remediate.
#
# DO NOT reuse this code for anything real. Lab account only.
# =====================================================================

terraform {
  required_version = ">= 1.6"

  required_providers {
    aws = {
      source  = "hashicorp/aws"
      version = "~> 6.0"
    }
    random = {
      source  = "hashicorp/random"
      version = "~> 3.6"
    }
  }
}

provider "aws" {
  region = var.region
}

variable "region" {
  description = "AWS region for the lab"
  type        = string
  default     = "eu-north-1"
}

# S3 bucket names must be unique across ALL AWS accounts worldwide,
# so a random suffix avoids name collisions.
resource "random_id" "suffix" {
  byte_length = 4
}

# ---------------------------------------------------------------------
# MISCONFIG 1: Publicly readable S3 bucket
# Real-world risk: the #1 source of cloud data leaks. Anyone on the
# internet can read every object in the bucket.
# ---------------------------------------------------------------------
resource "aws_s3_bucket" "public_data" {
  bucket = "cspm-lab-public-${random_id.suffix.hex}"
}

# Turns OFF the four safety switches that normally stop a bucket
# from being made public.
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = false
  block_public_policy     = false
  ignore_public_acls      = false
  restrict_public_buckets = false
}

# Grants read access to "*" = everyone, unauthenticated.
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "PublicRead"
      Effect    = "Allow"
      Principal = "*"
      Action    = "s3:GetObject"
      Resource  = "${aws_s3_bucket.public_data.arn}/*"
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_data]
}

# ---------------------------------------------------------------------
# MISCONFIG 2: Over-privileged IAM user
# Real-world risk: violates least privilege. If this user's credentials
# leak, the attacker gets full control of the entire account.
# ---------------------------------------------------------------------
resource "aws_iam_user" "overprivileged" {
  name = "lab-overprivileged-user"
}

# Inline policy allowing every action ("*") on every resource ("*").
resource "aws_iam_user_policy" "admin_wildcard" {
  name = "allow-everything"
  user = aws_iam_user.overprivileged.name

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = "*"
      Resource = "*"
    }]
  })
}

# ---------------------------------------------------------------------
# MISCONFIG 3: Security group open to the whole internet
# Real-world risk: SSH (22) and RDP (3389) exposed to 0.0.0.0/0 are
# constantly scanned and brute-forced by bots within minutes.
# ---------------------------------------------------------------------
data "aws_vpc" "default" {
  default = true
}

resource "aws_security_group" "wide_open" {
  name        = "lab-wide-open-sg"
  description = "Intentionally insecure: admin ports open to the internet"
  vpc_id      = data.aws_vpc.default.id

  ingress {
    description = "SSH from anywhere"
    from_port   = 22
    to_port     = 22
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  ingress {
    description = "RDP from anywhere"
    from_port   = 3389
    to_port     = 3389
    protocol    = "tcp"
    cidr_blocks = ["0.0.0.0/0"]
  }

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# ---------------------------------------------------------------------
# MISCONFIG 4: Unencrypted EBS volume
# Real-world risk: data at rest is readable if a snapshot or the
# volume is copied or shared. Also fails compliance requirements.
# Kept at 1 GB to keep cost negligible.
# ---------------------------------------------------------------------
data "aws_availability_zones" "available" {
  state = "available"
}

resource "aws_ebs_volume" "unencrypted" {
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = false

  tags = {
    Name = "lab-unencrypted-volume"
  }
}

# ---------------------------------------------------------------------
# MISCONFIG 5: No CloudTrail
# Deliberately NOT defined here. The risk is an ABSENCE: no audit log
# of who did what in the account. Checkov cannot flag code that does
# not exist; only Prowler, scanning the live account, will catch it.
# ---------------------------------------------------------------------
