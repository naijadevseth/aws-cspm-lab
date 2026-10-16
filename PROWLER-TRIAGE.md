# Prowler Triage: Live AWS Account Scan

**Tool:** Prowler 5.44.0
**Target:** Lab AWS account (account ID redacted), region `eu-north-1` plus global services (IAM, S3 account settings)
**Command:** `prowler aws --region eu-north-1`
**Scanned as:** IAM user `seth-admin` (temporary credentials via `aws login`; no access keys)
**Result:** 655 checks executed, **84 failed**, 43 passed (only checks with resources to evaluate produce a result)
**Failures by severity:** 4 Critical, 16 High, 44 Medium, 20 Low
**Stage:** Post-deployment. Scans what actually exists in AWS, after `terraform apply` of the insecure lab.

---

## Summary

84 failures trace back to **8 root causes**. Every finding is accounted for below.

| # | Root cause | Findings | Decision |
|---|---|---|---|
| A | Planted: public S3 bucket | 3 | Remediate |
| B | Planted: wildcard IAM policy on `lab-overprivileged-user` | 8 | Remediate |
| C | Planted: SSH/RDP open to the internet | 1 (see detection gap) | Remediate |
| D | Planted: unencrypted EBS volume | 1 | Remediate |
| E | Planted: no CloudTrail (plus 15 CloudWatch alarms that depend on it) | 20 | Remediate |
| F | My own admin setup (`seth-admin`, root) | 7 | Accept with documented reason |
| G | Unplanted account baseline gaps | 18 | Remediate |
| H | Not applicable to a single-account lab | 26 | Accept with documented reason |
| | **Total** | **84** | |

**Key lesson (again):** finding count is not risk count. One missing CloudTrail produced **20** findings. One wildcard policy produced **8**.

---

## 1. Planted misconfigurations (remediate)

### A. Public S3 bucket (3 findings)
Resource: `cspm-lab-public-7b7fa830`

| Severity | Check | Prowler says |
|---|---|---|
| Critical | `s3_bucket_public_access` | Bucket has public access due to bucket policy |
| High | `s3_bucket_level_public_access_block` | Block Public Access not configured for the bucket |
| High | `s3_bucket_cross_account_access` | Bucket policy allows cross-account access (`Principal: "*"`) |

**Remediation:** enable all four bucket-level Block Public Access settings; remove the `Principal: "*"` statement.
**Worth noting:** Prowler *passed* `s3_bucket_policy_public_write_access`, `s3_bucket_public_write_acl` and `s3_bucket_public_list_acl`. Our policy grants public **read** (`s3:GetObject`) only, not write or list, and Prowler distinguishes those precisely.

### B. Wildcard IAM policy (8 findings)
Resource: `lab-overprivileged-user`, inline policy `allow-everything` (`Action: "*"`, `Resource: "*"`)

| Severity | Check | Prowler says |
|---|---|---|
| Critical | `iam_inline_policy_no_administrative_privileges` | Inline policy allows `*:*` administrative privileges |
| High | `iam_inline_policy_allows_privilege_escalation` | Policy allows privilege escalation |
| High | `iam_inline_policy_no_full_access_to_cloudtrail` | Allows `cloudtrail:*`, so the user could switch off the audit log |
| High | `iam_user_hardware_mfa_enabled` | User has no MFA of any type |
| Medium | `iam_inline_policy_no_full_access_to_kms` | Allows `kms:*` (could delete encryption keys) |
| Medium | `iam_inline_policy_no_wildcard_marketplace_subscribe` | Allows Marketplace subscriptions (billing risk) |
| Medium | `iam_user_access_not_stale_to_bedrock` | Has Bedrock permissions it has never used |
| Low | `iam_policy_attached_only_to_group_or_roles` | Policy attached directly to a user |

**Remediation:** delete the user and inline policy. In a real environment: replace with a scoped policy granting only the needed actions, attached via a group or role.
**Mitigating context:** the user has **no password and no access keys** (Prowler confirms both as PASS), so nobody can currently authenticate as it. The risk is latent, not active, but one `CreateAccessKey` call away.

### C. SSH/RDP open to the internet (1 finding): a detection gap
Resource: `lab-wide-open-sg`

| Severity | Check | Prowler says |
|---|---|---|
| Low | `ec2_securitygroup_not_used` | Security group is not being used |

**Prowler did not flag the open ports 22 and 3389.** The scan banner shows `Scanning unused services and resources: False`. Because the security group is not attached to anything, Prowler skipped its internet-ingress checks and only reported that the group is unused.

This is the mirror image of CloudTrail:

| Misconfiguration | Checkov (code) | Prowler (live) |
|---|---|---|
| No CloudTrail | Missed (code doesn't exist) | **Caught** |
| SSH/RDP open to 0.0.0.0/0 | **Caught** | Missed (resource unused, skipped by default) |

Neither tool alone found all five planted issues. Together they did. An unattached-but-open security group is still a real risk: the moment someone attaches it to a new instance, that instance is exposed.
**Remediation:** remove both ingress rules (or delete the group). For the after-scan, also run Prowler with `--scan-unused-services` to confirm coverage.

### D. Unencrypted EBS volume (1 finding)
Resource: `vol-00134264a23c5431b` (`lab-unencrypted-volume`)

| Severity | Check | Prowler says |
|---|---|---|
| High | `ec2_ebs_volume_encryption` | Volume is unencrypted |

**Remediation:** EBS encryption cannot be switched on for an existing volume. Replace it with an encrypted volume (`encrypted = true`), and enable account-level default encryption (finding G).
**Note:** Prowler's message text calls it "EBS Snapshot ... is unencrypted", but the resource is the volume. Read the resource ID, not just the message.

### E. No CloudTrail (20 findings)

| Severity | Check | Count |
|---|---|---|
| High | `cloudtrail_multi_region_enabled`: no trail with logging exists | 1 |
| Medium | `cloudtrail_bedrock_logging_enabled` | 1 |
| Low | `cloudtrail_multi_region_enabled_logging_management_events`, `cloudtrail_s3_dataevents_read_enabled`, `cloudtrail_s3_dataevents_write_enabled` | 3 |
| Medium | `cloudwatch_*`: CIS alarms for root usage, sign-in without MFA, unauthorized API calls, IAM policy changes, security group / NACL / route table / VPC / gateway changes, CloudTrail and Config changes, KMS key deletion, S3 policy changes, Organizations changes, authentication failures | 15 |

Every CloudWatch finding has the same status text: *"No CloudWatch log groups found with metric filters or alarms associated."* The alarms read from CloudTrail logs, and there are none. **One fix (a multi-region trail delivering to CloudWatch Logs, plus the metric filters) resolves all 20.**

This is the finding Checkov could not produce: you cannot scan code for something that was never written.

---

## 2. My own admin setup (accept with documented reason)

| Severity | Check | Resource | Decision |
|---|---|---|---|
| Critical | `iam_aws_attached_policy_no_administrative_privileges` | `AdministratorAccess` | **Accept.** Attached to `Admins_group` for my own admin user. A single-person lab needs one admin identity. Production: IAM Identity Center with scoped permission sets. |
| High | `iam_group_administrator_access_policy` | `Admins_group` | **Accept.** Same root cause as above. |
| Critical | `iam_root_hardware_mfa_enabled` | root | **Accept.** Root has *virtual* MFA (PASS on `iam_root_mfa_enabled`). CIS prefers a hardware key for root; a cost/benefit call for a lab. |
| High | `iam_user_hardware_mfa_enabled` | `seth-admin` | **Accept.** Virtual MFA is enabled (PASS on `iam_user_mfa_enabled_console_access`). Hardware key is the stronger option. |
| High | `iam_avoid_root_usage` | root | **Accept, time-bound.** Root was used on scan day to finish account verification. Expected to clear once root stays unused. |
| Medium | `iam_user_access_not_stale_to_bedrock` | `seth-admin` | **Accept.** Side effect of AdministratorAccess. |
| Medium | `iam_role_access_not_stale_to_bedrock` | `AWSServiceRoleForSupport` | **Accept.** AWS-managed service-linked role; not mine to change. |

These are recorded rather than hidden. The honest version of a report says "my own admin user is also flagged, and here is why that is acceptable for this context."

---

## 3. Unplanted account baseline gaps (remediate)

Real findings I didn't plant. These are what a fresh AWS account looks like before hardening.

| Severity | Check | Fix |
|---|---|---|
| High | `s3_account_level_public_access_blocks` | Enable S3 Block Public Access **for the whole account**: a safety net for every future bucket |
| High | `ec2_ebs_default_encryption` | Turn on EBS encryption by default for the region |
| High | `ec2_networkacl_allow_ingress_any_port` | Default VPC network ACL `acl-089c6caf5d97a6208` allows all inbound traffic (AWS default) |
| Medium | `ec2_networkacl_allow_ingress_tcp_port_22`, `..._3389` | Same default NACL; tighten, or rely on security groups and document it |
| Medium | `iam_password_policy_*` (6 checks) + Low `iam_password_policy_lowercase` | Set an account password policy: min length 14, complexity, reuse prevention 24, expiry |
| Medium | `config_recorder_all_regions_enabled` | Enable AWS Config to record configuration history (pairs with CloudTrail) |
| Medium | `account_maintain_different_contact_details_to_security_billing_and_operations` | Set separate security / billing / operations contacts |
| Medium | `s3_bucket_server_access_logging_enabled` | Same as Checkov CKV_AWS_18 |
| Medium | `s3_bucket_object_versioning` | Same as Checkov CKV_AWS_21 |
| Medium | `s3_bucket_secure_transport_policy` | Deny non-HTTPS requests (`aws:SecureTransport = false`) in the bucket policy |
| Low | `accessanalyzer_enabled` | Enable IAM Access Analyzer (free; continuously flags external access) |

**18 findings.** Most are one-time account settings, so a small number of changes clears them.

---

## 4. Not applicable to a single-account lab (accept with documented reason)

| Group | Checks | Reason |
|---|---|---|
| AWS Organizations (5) | `organizations_account_part_of_organizations`, `organizations_scp_check_deny_regions` (High), `organizations_opt_out_ai_services_policy`, `organizations_tags_policies_enabled_and_attached`, `config_delegated_admin_and_org_aggregator_all_regions` (High) | Multi-account governance. This is one standalone account. Production: use Organizations with SCPs. |
| Services not in use (7) | `bedrock_guardrails_configured`, `bedrock_model_invocation_logging_enabled`, `sagemaker_clarify_exists`, `sagemaker_models_monitor_enabled`, `sagemaker_models_registry_in_use`, `ssmincidents_enabled_with_plans`, `fms_policy_compliant` | No Bedrock, SageMaker, Incident Manager or Firewall Manager workloads exist. |
| Backup / resilience (5) | `backup_vaults_exist`, `ec2_ebs_volume_protected_by_backup_plan`, `ec2_ebs_volume_snapshots_exists` (High), `s3_bucket_cross_region_replication`, `vpc_different_regions` | Disaster-recovery controls. No data worth backing up; adds cost. |
| S3 hardening beyond baseline (5) | `s3_bucket_kms_encryption`, `s3_bucket_no_mfa_delete`, `s3_bucket_object_lock`, `s3_bucket_lifecycle_enabled`, `s3_bucket_event_notifications_enabled` | Bucket already encrypted with SSE-S3 (Prowler PASS on `s3_bucket_default_encryption`). Customer-managed KMS, MFA Delete and Object Lock suit regulated data. Matches Checkov decisions. |
| Identity / support extras (4) | `iam_check_saml_providers_sts`, `iam_securityaudit_role_created`, `iam_support_role_created`, `trustedadvisor_premium_support_plan_subscribed` | Federation, dedicated audit/support roles and paid support are organisational controls. |

**26 findings.**

---

## Notable PASSes

- `iam_root_mfa_enabled` and `iam_no_root_access_key`: the two most important root controls are in place.
- No access keys exist for any user (`iam_rotate_access_key_90_days`, `iam_user_accesskey_unused`). Using `aws login` temporary credentials instead of access keys kept this whole class of finding at zero.
- `s3_bucket_default_encryption`: AWS now encrypts new buckets with SSE-S3 by default, so the "unencrypted bucket" problem of older AWS accounts no longer appears.

And a quirk worth knowing: `iam_administrator_access_with_mfa` **passed** for `Admins_group` with the message *"provides non-administrative access"*, while two other checks flag the same group for AdministratorAccess. Tools can contradict each other and themselves. Read the evidence, not only the verdict.

---

## Checkov vs Prowler: who caught what

| Planted issue | Checkov (pre-deploy, code) | Prowler (post-deploy, live) |
|---|---|---|
| Public S3 bucket | Caught (6 findings) | Caught (3 findings) |
| Wildcard IAM policy | Caught (10 findings) | Caught (8 findings) |
| SSH/RDP open to internet | Caught | **Missed by default** (unused resource skipped) |
| Unencrypted EBS | Caught | Caught |
| No CloudTrail | **Missed** (no code to scan) | Caught (20 findings) |

Prowler also found **account-level** issues no IaC scanner can see, because they were never in the Terraform: password policy, account-wide Block Public Access, EBS default encryption, the default NACL, root usage.

**Conclusion:** code scanning and live-account scanning cover different blind spots. Use both.

---

## Remediation plan

1. Fix A–E in Terraform (secure `main.tf`), plus the bucket-level items from section 3.
2. Apply account baseline fixes (section 3): account Block Public Access, EBS default encryption, password policy, Access Analyzer, AWS Config, CloudTrail + CloudWatch alarms.
3. Re-run Checkov → `reports/checkov-after.txt`.
4. Re-run Prowler, including `--scan-unused-services` → compare against this baseline.

## Evidence

- Raw Prowler output (CSV / HTML / JSON): kept locally in `output/`, excluded from Git because it contains the account ID and resource identifiers.
- This triage covers all 84 failed findings from the 2026-10-16 baseline scan.
