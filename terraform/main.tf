# =====================================================================
# aws-cspm-lab: REMEDIATED (SECURE) VERSION
#
# This replaces the intentionally insecure lab. Each "FIX" comment maps
# back to a finding in CHECKOV-TRIAGE.md / PROWLER-TRIAGE.md.
# Accepted risks are suppressed IN CODE with a written reason
# using Checkov skip comments, so nothing is silently ignored.
#
# Compare with the insecure version:  git diff HEAD -- terraform/main.tf
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

# Personal data lives in terraform.tfvars, which .gitignore keeps
# out of GitHub. See terraform.tfvars.example.
variable "alert_email" {
  description = "Email address that receives security alarm notifications"
  type        = string
}

data "aws_caller_identity" "current" {}

locals {
  account_id = data.aws_caller_identity.current.account_id
  trail_name = "cspm-lab-trail"
  trail_arn  = "arn:aws:cloudtrail:${var.region}:${local.account_id}:trail/${local.trail_name}"
}

resource "random_id" "suffix" {
  byte_length = 4
}

# =====================================================================
# ACCOUNT-LEVEL BASELINE (Prowler-only findings: never in the old code)
# =====================================================================

# FIX: s3_account_level_public_access_blocks (High)
# A safety net for EVERY bucket in the account, including future ones.
resource "aws_s3_account_public_access_block" "account" {
  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FIX: ec2_ebs_default_encryption (High)
# Every new EBS volume in this region is encrypted automatically.
resource "aws_ebs_encryption_by_default" "this" {
  enabled = true
}

# FIX: iam_password_policy_* (7 findings)
resource "aws_iam_account_password_policy" "strict" {
  minimum_password_length        = 14
  require_lowercase_characters   = true
  require_uppercase_characters   = true
  require_numbers                = true
  require_symbols                = true
  password_reuse_prevention      = 24
  max_password_age               = 90
  allow_users_to_change_password = true
}

# FIX: accessanalyzer_enabled (Low)
# Free. Continuously flags resources shared outside the account.
resource "aws_accessanalyzer_analyzer" "account" {
  analyzer_name = "cspm-lab-analyzer"
  type          = "ACCOUNT"
}

# FIX: ec2_networkacl_allow_ingress_* (1 High, 2 Medium)
# The default VPC's network ACL allowed ALL inbound traffic from the
# internet (AWS default). Restrict inbound to traffic from inside the
# VPC. Trade-off: NACLs are stateless, so an instance in this VPC could
# no longer receive replies from the internet. Acceptable here because
# nothing runs in the default VPC.
data "aws_vpc" "default" {
  default = true
}

data "aws_network_acls" "default" {
  vpc_id = data.aws_vpc.default.id

  filter {
    name   = "default"
    values = ["true"]
  }
}

resource "aws_default_network_acl" "default" {
  default_network_acl_id = tolist(data.aws_network_acls.default.ids)[0]

  ingress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = data.aws_vpc.default.cidr_block
  }

  egress {
    rule_no    = 100
    action     = "allow"
    protocol   = "-1"
    from_port  = 0
    to_port    = 0
    cidr_block = "0.0.0.0/0"
  }

  lifecycle {
    ignore_changes = [subnet_ids]
  }
}

# FIX: ec2_securitygroup_default_restrict_traffic (High, CIS 5.4)
# Only visible with --scan-unused-services. Every VPC has a "default"
# security group that AWS attaches automatically when you launch something
# without choosing a group. Out of the box it allows all traffic between
# members and all outbound traffic. Declaring it with NO rules strips them,
# so nothing can accidentally inherit permissive access.
resource "aws_default_security_group" "default" {
  vpc_id = data.aws_vpc.default.id
}

# ---------------------------------------------------------------------
# Round 2 fixes: findings that only appeared in the full after-scan
# ---------------------------------------------------------------------

# FIX: ec2_ebs_snapshot_account_block_public_access (High)
# Stops anyone in this account from sharing an EBS snapshot publicly,
# a known way disk contents leak.
resource "aws_ebs_snapshot_block_public_access" "this" {
  state = "block-all-sharing"
}

# FIX: ec2_instance_account_imdsv2_enabled (High)
# New EC2 instances must use IMDSv2 (session tokens) for the metadata
# service. IMDSv1 was abused in the 2019 Capital One breach via SSRF.
resource "aws_ec2_instance_metadata_defaults" "this" {
  http_tokens                 = "required"
  http_put_response_hop_limit = 2
}

# FIX: vpc_subnet_no_public_ip_by_default (High x3)
# Default subnets hand every new instance a public IP automatically.
# Turning that off means a server is only internet-facing if someone
# deliberately asks for it.
resource "aws_default_subnet" "default" {
  for_each = toset(data.aws_availability_zones.available.names)

  availability_zone       = each.value
  map_public_ip_on_launch = false
}

# =====================================================================
# MISCONFIG 1 FIXED: S3 bucket is now private
# (Name kept so the plan shows an in-place fix rather than a new bucket.)
# =====================================================================
resource "aws_s3_bucket" "public_data" {
  #checkov:skip=CKV_AWS_144:Cross-region replication is a DR control; not justified for an empty lab bucket
  #checkov:skip=CKV2_AWS_61:Lifecycle rules are cost/retention management, not a security control here
  #checkov:skip=CKV2_AWS_62:Event notifications out of scope for this lab
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES256) is sufficient; customer-managed KMS adds cost without lab benefit
  bucket        = "cspm-lab-public-${random_id.suffix.hex}"
  force_destroy = true
}

# FIX: CKV_AWS_53/54/55/56, CKV2_AWS_6, s3_bucket_level_public_access_block
resource "aws_s3_bucket_public_access_block" "public_data" {
  bucket = aws_s3_bucket.public_data.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

# FIX: CKV_AWS_70, s3_bucket_public_access, s3_bucket_cross_account_access
# The "Principal: *" ALLOW is gone. The only statement left DENIES
# any request not made over HTTPS (fixes s3_bucket_secure_transport_policy).
resource "aws_s3_bucket_policy" "public_read" {
  bucket = aws_s3_bucket.public_data.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Sid       = "DenyInsecureTransport"
      Effect    = "Deny"
      Principal = "*"
      Action    = "s3:*"
      Resource = [
        aws_s3_bucket.public_data.arn,
        "${aws_s3_bucket.public_data.arn}/*"
      ]
      Condition = { Bool = { "aws:SecureTransport" = "false" } }
    }]
  })

  depends_on = [aws_s3_bucket_public_access_block.public_data]
}

# FIX: CKV_AWS_21, s3_bucket_object_versioning
resource "aws_s3_bucket_versioning" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  versioning_configuration {
    status = "Enabled"
  }
}

# Explicit (AWS already does this by default, but code should say so)
resource "aws_s3_bucket_server_side_encryption_configuration" "public_data" {
  bucket = aws_s3_bucket.public_data.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# FIX: CKV_AWS_18, s3_bucket_server_access_logging_enabled
resource "aws_s3_bucket_logging" "public_data" {
  bucket        = aws_s3_bucket.public_data.id
  target_bucket = aws_s3_bucket.logs.id
  target_prefix = "s3-access/data/"
}

# =====================================================================
# MISCONFIG 2 FIXED: overprivileged IAM user removed
# lab-overprivileged-user and its "*:*" inline policy are deleted simply
# by no longer being in the code. Terraform destroys them on apply.
# =====================================================================

# =====================================================================
# MISCONFIG 3 FIXED: no admin ports open to the internet
# =====================================================================
resource "aws_security_group" "wide_open" {
  #checkov:skip=CKV2_AWS_5:Lab artifact kept to show the in-place fix; it is not attached to anything
  #checkov:skip=CKV_AWS_382:Egress to 0.0.0.0/0 is the AWS default and the group has no attached resources
  name        = "lab-wide-open-sg"
  description = "Remediated: no inbound rules"
  vpc_id      = data.aws_vpc.default.id

  # "ingress = []" is required. Simply deleting the ingress blocks would
  # NOT remove the existing rules (Terraform attributes-as-blocks rule).
  ingress = []

  egress {
    description = "All outbound traffic"
    from_port   = 0
    to_port     = 0
    protocol    = "-1"
    cidr_blocks = ["0.0.0.0/0"]
  }
}

# =====================================================================
# MISCONFIG 4 FIXED: EBS volume is encrypted
# Encryption cannot be switched on for an existing volume, so Terraform
# will REPLACE it (destroy old, create new). Watch for "-/+" in the plan.
# =====================================================================
data "aws_availability_zones" "available" {
  #checkov:skip=CKV_AWS_394:AZ pinning is a reliability concern, not a security control
  state = "available"
}

resource "aws_ebs_volume" "unencrypted" {
  #checkov:skip=CKV_AWS_189:Encrypted with the AWS-managed EBS key; a customer-managed key adds cost without lab benefit
  availability_zone = data.aws_availability_zones.available.names[0]
  size              = 1
  type              = "gp3"
  encrypted         = true

  tags = {
    Name = "lab-encrypted-volume"
  }
}

# =====================================================================
# MISCONFIG 5 FIXED: CloudTrail audit logging
# FIX: cloudtrail_multi_region_enabled (High) + management events
# =====================================================================

# Central log bucket: receives CloudTrail logs AND S3 access logs.
resource "aws_s3_bucket" "logs" {
  #checkov:skip=CKV_AWS_18:A log bucket logging to itself creates an infinite loop
  #checkov:skip=CKV_AWS_144:Cross-region replication is a DR control; not justified for a lab
  #checkov:skip=CKV2_AWS_61:Lifecycle rules are cost management, not a security control here
  #checkov:skip=CKV2_AWS_62:Event notifications out of scope for this lab
  #checkov:skip=CKV_AWS_145:SSE-S3 (AES256) is sufficient for the lab
  bucket        = "cspm-lab-logs-${random_id.suffix.hex}"
  force_destroy = true
}

resource "aws_s3_bucket_public_access_block" "logs" {
  bucket = aws_s3_bucket.logs.id

  block_public_acls       = true
  block_public_policy     = true
  ignore_public_acls      = true
  restrict_public_buckets = true
}

resource "aws_s3_bucket_versioning" "logs" {
  bucket = aws_s3_bucket.logs.id
  versioning_configuration {
    status = "Enabled"
  }
}

resource "aws_s3_bucket_server_side_encryption_configuration" "logs" {
  bucket = aws_s3_bucket.logs.id
  rule {
    apply_server_side_encryption_by_default {
      sse_algorithm = "AES256"
    }
  }
}

# Least privilege: each AWS service may write ONLY to its own prefix,
# and only on behalf of THIS trail / THIS bucket (aws:SourceArn).
resource "aws_s3_bucket_policy" "logs" {
  bucket = aws_s3_bucket.logs.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [
      {
        Sid       = "CloudTrailAclCheck"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:GetBucketAcl"
        Resource  = aws_s3_bucket.logs.arn
        Condition = { StringEquals = { "aws:SourceArn" = local.trail_arn } }
      },
      {
        Sid       = "CloudTrailWrite"
        Effect    = "Allow"
        Principal = { Service = "cloudtrail.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/AWSLogs/${local.account_id}/*"
        Condition = {
          StringEquals = {
            "s3:x-amz-acl"  = "bucket-owner-full-control"
            "aws:SourceArn" = local.trail_arn
          }
        }
      },
      {
        Sid       = "S3ServerAccessLogs"
        Effect    = "Allow"
        Principal = { Service = "logging.s3.amazonaws.com" }
        Action    = "s3:PutObject"
        Resource  = "${aws_s3_bucket.logs.arn}/s3-access/*"
        Condition = {
          ArnLike      = { "aws:SourceArn" = aws_s3_bucket.public_data.arn }
          StringEquals = { "aws:SourceAccount" = local.account_id }
        }
      },
      {
        Sid       = "DenyInsecureTransport"
        Effect    = "Deny"
        Principal = "*"
        Action    = "s3:*"
        Resource  = [aws_s3_bucket.logs.arn, "${aws_s3_bucket.logs.arn}/*"]
        Condition = { Bool = { "aws:SecureTransport" = "false" } }
      }
    ]
  })

  depends_on = [aws_s3_bucket_public_access_block.logs]
}

# CloudTrail also streams events to CloudWatch Logs, so the alarms
# below can react within minutes instead of someone reading S3 files.
resource "aws_cloudwatch_log_group" "trail" {
  #checkov:skip=CKV_AWS_158:Log group encrypted by CloudWatch by default; a customer-managed KMS key adds cost
  name              = "/aws/cloudtrail/cspm-lab"
  retention_in_days = 365
}

resource "aws_iam_role" "trail_to_cloudwatch" {
  name = "cspm-lab-cloudtrail-to-cloudwatch"

  # Round 2 fix: iam_role_cross_service_confused_deputy_prevention (High).
  # Without these conditions, CloudTrail acting for ANY account could be
  # tricked into using this role. Now only OUR trail in OUR account can.
  assume_role_policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect    = "Allow"
      Principal = { Service = "cloudtrail.amazonaws.com" }
      Action    = "sts:AssumeRole"
      Condition = {
        StringEquals = {
          "aws:SourceAccount" = local.account_id
          "aws:SourceArn"     = local.trail_arn
        }
      }
    }]
  })
}

# Only the two actions CloudTrail needs, on only this log group.
resource "aws_iam_role_policy" "trail_to_cloudwatch" {
  name = "write-trail-log-group"
  role = aws_iam_role.trail_to_cloudwatch.id

  policy = jsonencode({
    Version = "2012-10-17"
    Statement = [{
      Effect   = "Allow"
      Action   = ["logs:CreateLogStream", "logs:PutLogEvents"]
      Resource = "${aws_cloudwatch_log_group.trail.arn}:*"
    }]
  })
}

resource "aws_cloudtrail" "main" {
  #checkov:skip=CKV_AWS_35:Logs encrypted with SSE-S3; a customer-managed KMS key costs ~$1/month, not justified for the lab
  #checkov:skip=CKV_AWS_252:Alerting handled by CloudWatch metric filters and alarms instead of per-file SNS notifications
  name                          = local.trail_name
  s3_bucket_name                = aws_s3_bucket.logs.id
  is_multi_region_trail         = true
  include_global_service_events = true
  enable_log_file_validation    = true # detects tampering with log files

  cloud_watch_logs_group_arn = "${aws_cloudwatch_log_group.trail.arn}:*"
  cloud_watch_logs_role_arn  = aws_iam_role.trail_to_cloudwatch.arn

  depends_on = [
    aws_s3_bucket_policy.logs,
    aws_iam_role_policy.trail_to_cloudwatch
  ]
}

# =====================================================================
# CIS ALERTING: 15 metric filters + alarms
# FIX: all 15 cloudwatch_* findings. One map, one loop.
# Patterns follow the CIS AWS Foundations Benchmark.
# =====================================================================

# Not KMS-encrypted on purpose: CloudWatch alarms CANNOT publish to a topic
# encrypted with the AWS-managed SNS key (its key policy can't grant
# CloudWatch access). Following the scanner here would silently break
# every alert. A customer-managed key would work but costs ~$1/month.
resource "aws_sns_topic" "security_alarms" {
  #checkov:skip=CKV_AWS_26:AWS-managed SNS key blocks CloudWatch alarm delivery; CMK not justified for lab
  name = "cspm-lab-security-alarms"
}

resource "aws_sns_topic_subscription" "email" {
  topic_arn = aws_sns_topic.security_alarms.arn
  protocol  = "email"
  endpoint  = var.alert_email
}

locals {
  cis_alarms = {
    "unauthorized-api-calls"   = "{ ($.errorCode = \"*UnauthorizedOperation\") || ($.errorCode = \"AccessDenied*\") }"
    "console-signin-no-mfa"    = "{ ($.eventName = \"ConsoleLogin\") && ($.additionalEventData.MFAUsed != \"Yes\") }"
    "root-account-usage"       = "{ $.userIdentity.type = \"Root\" && $.userIdentity.invokedBy NOT EXISTS && $.eventType != \"AwsServiceEvent\" }"
    "iam-policy-changes"       = "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) || ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) || ($.eventName = PutRolePolicy) || ($.eventName = PutUserPolicy) || ($.eventName = CreatePolicy) || ($.eventName = DeletePolicy) || ($.eventName = CreatePolicyVersion) || ($.eventName = DeletePolicyVersion) || ($.eventName = AttachRolePolicy) || ($.eventName = DetachRolePolicy) || ($.eventName = AttachUserPolicy) || ($.eventName = DetachUserPolicy) || ($.eventName = AttachGroupPolicy) || ($.eventName = DetachGroupPolicy) }"
    "cloudtrail-config-change" = "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) || ($.eventName = DeleteTrail) || ($.eventName = StartLogging) || ($.eventName = StopLogging) }"
    "console-auth-failures"    = "{ ($.eventName = ConsoleLogin) && ($.errorMessage = \"Failed authentication\") }"
    "kms-cmk-disable-delete"   = "{ ($.eventSource = kms.amazonaws.com) && (($.eventName = DisableKey) || ($.eventName = ScheduleKeyDeletion)) }"
    "s3-bucket-policy-changes" = "{ ($.eventSource = s3.amazonaws.com) && (($.eventName = PutBucketAcl) || ($.eventName = PutBucketPolicy) || ($.eventName = PutBucketCors) || ($.eventName = PutBucketLifecycle) || ($.eventName = PutBucketReplication) || ($.eventName = DeleteBucketPolicy) || ($.eventName = DeleteBucketCors) || ($.eventName = DeleteBucketLifecycle) || ($.eventName = DeleteBucketReplication)) }"
    "aws-config-changes"       = "{ ($.eventSource = config.amazonaws.com) && (($.eventName = StopConfigurationRecorder) || ($.eventName = DeleteDeliveryChannel) || ($.eventName = PutDeliveryChannel) || ($.eventName = PutConfigurationRecorder)) }"
    "security-group-changes"   = "{ ($.eventName = AuthorizeSecurityGroupIngress) || ($.eventName = AuthorizeSecurityGroupEgress) || ($.eventName = RevokeSecurityGroupIngress) || ($.eventName = RevokeSecurityGroupEgress) || ($.eventName = CreateSecurityGroup) || ($.eventName = DeleteSecurityGroup) }"
    "nacl-changes"             = "{ ($.eventName = CreateNetworkAcl) || ($.eventName = CreateNetworkAclEntry) || ($.eventName = DeleteNetworkAcl) || ($.eventName = DeleteNetworkAclEntry) || ($.eventName = ReplaceNetworkAclEntry) || ($.eventName = ReplaceNetworkAclAssociation) }"
    "network-gateway-changes"  = "{ ($.eventName = CreateCustomerGateway) || ($.eventName = DeleteCustomerGateway) || ($.eventName = AttachInternetGateway) || ($.eventName = CreateInternetGateway) || ($.eventName = DeleteInternetGateway) || ($.eventName = DetachInternetGateway) }"
    "route-table-changes"      = "{ ($.eventSource = ec2.amazonaws.com) && (($.eventName = CreateRoute) || ($.eventName = CreateRouteTable) || ($.eventName = ReplaceRoute) || ($.eventName = ReplaceRouteTableAssociation) || ($.eventName = DeleteRouteTable) || ($.eventName = DeleteRoute) || ($.eventName = DisassociateRouteTable)) }"
    "vpc-changes"              = "{ ($.eventName = CreateVpc) || ($.eventName = DeleteVpc) || ($.eventName = ModifyVpcAttribute) || ($.eventName = AcceptVpcPeeringConnection) || ($.eventName = CreateVpcPeeringConnection) || ($.eventName = DeleteVpcPeeringConnection) || ($.eventName = RejectVpcPeeringConnection) || ($.eventName = AttachClassicLinkVpc) || ($.eventName = DetachClassicLinkVpc) || ($.eventName = DisableVpcClassicLink) || ($.eventName = EnableVpcClassicLink) }"
    # Round 2 fix: added CancelHandshake, CreateOrganization, EnableAllFeatures.
    # Prowler requires ALL 21 Organizations events; the first version had 18.
    "organizations-changes" = "{ ($.eventSource = organizations.amazonaws.com) && (($.eventName = AcceptHandshake) || ($.eventName = AttachPolicy) || ($.eventName = CancelHandshake) || ($.eventName = CreateAccount) || ($.eventName = CreateOrganization) || ($.eventName = CreateOrganizationalUnit) || ($.eventName = CreatePolicy) || ($.eventName = DeclineHandshake) || ($.eventName = DeleteOrganization) || ($.eventName = DeleteOrganizationalUnit) || ($.eventName = DeletePolicy) || ($.eventName = DetachPolicy) || ($.eventName = DisablePolicyType) || ($.eventName = EnableAllFeatures) || ($.eventName = EnablePolicyType) || ($.eventName = InviteAccountToOrganization) || ($.eventName = LeaveOrganization) || ($.eventName = MoveAccount) || ($.eventName = RemoveAccountFromOrganization) || ($.eventName = UpdatePolicy) || ($.eventName = UpdateOrganizationalUnit)) }"
  }
}

resource "aws_cloudwatch_log_metric_filter" "cis" {
  for_each = local.cis_alarms

  name           = "cis-${each.key}"
  log_group_name = aws_cloudwatch_log_group.trail.name
  pattern        = each.value

  metric_transformation {
    name      = "cis-${each.key}"
    namespace = "CISBenchmark"
    value     = "1"
  }
}

resource "aws_cloudwatch_metric_alarm" "cis" {
  for_each = local.cis_alarms

  alarm_name          = "cis-${each.key}"
  alarm_description   = "CIS AWS Foundations Benchmark alarm: ${each.key}"
  namespace           = "CISBenchmark"
  metric_name         = aws_cloudwatch_log_metric_filter.cis[each.key].metric_transformation[0].name
  statistic           = "Sum"
  period              = 300
  evaluation_periods  = 1
  threshold           = 1
  comparison_operator = "GreaterThanOrEqualToThreshold"
  treat_missing_data  = "notBreaching"
  alarm_actions       = [aws_sns_topic.security_alarms.arn]
}
