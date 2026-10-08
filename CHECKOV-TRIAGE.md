# Checkov Triage: Infrastructure-as-Code Scan

**Tool:** Checkov 3.3.26 (Prisma Cloud)
**Target:** `terraform/main.tf` (intentionally insecure lab environment)
**Command:** `checkov -d terraform`
**Result:** 11 passed, **30 failed**, 0 skipped
**Stage:** Pre-deployment ("shift-left"). Nothing has been created in AWS yet.

---

## Summary

30 failed checks trace back to **4 planted root causes (19 findings)** plus **11 findings we did not plant**.

| Category | Findings | Decision |
|---|---|---|
| Planted misconfigurations | 19 | Remediate |
| Unplanted, real security value | 4 | 2 remediate, 2 accept with reason |
| Context-dependent hardening / lab artifacts | 7 | Accept with documented reason |

**Key lesson:** finding count is not risk count. One misconfigured resource can trigger many checks. The S3 public access block alone produced 4 findings, and one wildcard IAM policy produced 10. Triage groups findings by root cause before deciding what to do.

---

## 1. Planted misconfigurations (remediate)

### Root cause A: Public S3 bucket (6 findings)
Resources: `aws_s3_bucket_public_access_block.public_data`, `aws_s3_bucket_policy.public_read`, `aws_s3_bucket.public_data`

| Check | Description |
|---|---|
| CKV_AWS_53 | Block public ACLs disabled |
| CKV_AWS_54 | Block public policy disabled |
| CKV_AWS_55 | Ignore public ACLs disabled |
| CKV_AWS_56 | Restrict public buckets disabled |
| CKV2_AWS_6 | Bucket lacks an effective public access block |
| CKV_AWS_70 | Bucket policy allows an action for any principal (`"*"`) |

**Risk:** anyone on the internet can read every object. The most common cause of cloud data leaks.
**Remediation:** set all four public access block settings to `true`; remove the `Principal = "*"` policy.

### Root cause B: Wildcard IAM policy (10 findings)
Resource: `aws_iam_user_policy.admin_wildcard` (`Action = "*"`, `Resource = "*"`)

| Check | Description |
|---|---|
| CKV_AWS_62 | Full `"*:*"` administrative privileges |
| CKV2_AWS_40 | Full IAM privileges |
| CKV_AWS_287 | Allows credentials exposure |
| CKV_AWS_288 | Allows data exfiltration |
| (see baseline file) | Allows privilege escalation |
| (see baseline file) | Allows permissions management / resource exposure without constraints |
| (see baseline file) | Allows write access without constraints |
| (see baseline file) | `"*"` used as the statement's actions |
| (see baseline file) | `"*"` used as the resource for restrictable actions |
| (see baseline file) | Policy attached directly to a user instead of a group or role |

**Risk:** violates least privilege. If this user's credentials leak, the attacker controls the entire account.
**Remediation:** replace with a scoped policy granting only the specific actions and resources needed; attach via a group or role, not directly to the user.

### Root cause C: Admin ports open to the internet (2 findings)
Resource: `aws_security_group.wide_open`

| Check | Description |
|---|---|
| (see baseline file) | Ingress from 0.0.0.0/0 to port 22 (SSH) |
| (see baseline file) | Ingress from 0.0.0.0/0 to port 3389 (RDP) |

**Risk:** SSH and RDP exposed to the internet are scanned and brute-forced by bots within minutes.
**Remediation:** remove both rules, or restrict to a single trusted IP (`x.x.x.x/32`). Prefer AWS Systems Manager Session Manager, which needs no inbound ports at all.

### Root cause D: Unencrypted EBS volume (1 finding)
Resource: `aws_ebs_volume.unencrypted`

| Check | Description |
|---|---|
| CKV_AWS_3 | EBS volume not encrypted |

**Risk:** data at rest is readable if the volume or a snapshot is copied or shared.
**Remediation:** set `encrypted = true` (and enable EBS encryption by default at the account level).

### Root cause E: No CloudTrail (0 findings, expected)
CloudTrail was deliberately left out of the code. **Checkov cannot flag a resource that does not exist.** Detecting this absence requires scanning the live account (Prowler, CIS AWS Foundations Benchmark).

---

## 2. Unplanted findings with real security value

| Check | Resource | Description | Decision |
|---|---|---|---|
| CKV_AWS_18 | S3 bucket | Access logging not enabled | **Remediate.** No record of who accessed the data; supports incident investigation. |
| CKV_AWS_21 | S3 bucket | Versioning not enabled | **Remediate.** Protects against accidental deletion and ransomware-style overwrites. |
| CKV_AWS_273 | IAM user | Access should use SSO, not IAM users | **Accept for lab.** IAM Identity Center is best practice for organisations; a single-user lab with MFA is acceptable. Production: use IAM Identity Center. |
| (see baseline file) | Security group | Egress to 0.0.0.0/0 on all ports | **Accept for lab.** This is the AWS default and no instances use the group. Production: restrict egress to reduce exfiltration paths. |

---

## 3. Context-dependent hardening and lab artifacts (accept with reason)

| Check | Description | Reason accepted |
|---|---|---|
| CKV_AWS_144 | S3 cross-region replication | Disaster-recovery control; doubles storage cost. Appropriate for production data, not a lab. |
| CKV2_AWS_61 | S3 lifecycle configuration | Cost/retention management, not a direct security control. |
| CKV2_AWS_62 | S3 event notifications | Useful for alerting pipelines; out of scope for this lab. |
| CKV_AWS_145 | S3 encrypted with KMS (CMK) | S3 encrypts with AWS-managed keys (SSE-S3) by default. Customer-managed keys add cost and key-management overhead; required in some compliance regimes. |
| CKV_AWS_189 | EBS encrypted with a customer-managed KMS key | Same reasoning: fixing CKV_AWS_3 with the AWS-managed key is sufficient for the lab. |
| CKV2_AWS_5 | Security group not attached to a resource | Lab artifact: the group exists only to be detected. |
| CKV_AWS_394 | Availability-zone data source not pinned | Infrastructure reliability/predictability, not a security risk. |

---

## Notable PASS: a false sense of security

**CKV2_AWS_2** ("only encrypted EBS volumes are attached to EC2 instances") **passed** for our *unencrypted* volume, because the volume is not attached to any instance, so the rule's condition never applies.

A PASS means "this specific rule did not trigger", not "this resource is safe". Always read what a check actually tests. (Same lesson as the Trivy scan that reported zero findings because it scanned zero files.)

---

## Evidence

- Baseline output with exact check IDs: `reports/checkov-before.txt`
- Re-scan after remediation: `reports/checkov-after.txt` (pending)
