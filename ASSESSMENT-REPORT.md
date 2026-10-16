# AWS Cloud Security Posture Assessment

**Scope:** Single AWS lab account (account ID redacted), region `eu-north-1` plus global services
**Benchmark:** CIS AWS Foundations Benchmark, via Prowler's compliance mapping
**Tools:** Terraform 1.16, Checkov 3.3 (code scanning), Prowler 5.44 (live account scanning)
**Assessment date:** 16 October 2026
**Author:** Seth Owolabi

---

## 1. Executive summary

I built a deliberately misconfigured AWS environment with Terraform, detected the misconfigurations with two independent tools, remediated them as code, and verified each fix in the live account.

| Measure | Before | After |
|---|---|---|
| Checkov failed checks (code) | 30 | **0** (17 accepted risks documented in code) |
| Planted misconfigurations open | 5 | **0** |
| CIS CloudWatch alarms in place | 0 of 15 | **15 of 15** |
| Prowler Critical findings | 4 | **2** (both accepted, see section 6) |
| Prowler S3 Critical + High | 4 | **0** |
| Baseline Prowler failures resolved | – | **51 of 84** |

**Key finding:** neither tool caught all five planted misconfigurations on its own. Checkov missed the absent CloudTrail, because there was no code to scan. Prowler's default scan missed SSH/RDP open to the internet, because it skips unused resources. Together they caught everything.

---

## 2. Method

```
Terraform (insecure)  ->  Checkov  ->  terraform apply  ->  Prowler (baseline)
         |                                                        |
         v                                                        v
Terraform (secure)    ->  Checkov  ->  terraform apply  ->  Prowler (full scan)
                                                                  |
                                                                  v
                                            Round 2 fixes  ->  Targeted re-checks
```

1. **Build insecure:** Terraform deployed five planted misconfigurations (section 3).
2. **Scan code:** Checkov scanned the Terraform before deployment (shift-left).
3. **Deploy and scan live:** Prowler scanned the real account against CIS and other frameworks.
4. **Triage:** every finding was grouped by root cause and marked *remediate* or *accept with reason*. See `CHECKOV-TRIAGE.md` and `PROWLER-TRIAGE.md`.
5. **Remediate as code:** a secure `main.tf` replaced the insecure one. The Git history shows every change.
6. **Verify:** Checkov rescan, a full Prowler rescan with `--scan-unused-services`, a second round of fixes, then targeted re-checks.

**Access model:** all work ran as an IAM admin user with MFA, using `aws login` short-lived credentials. No long-lived access keys were ever created, and Prowler confirmed zero access keys in the account.

---

## 3. Planted misconfigurations and results

| # | Misconfiguration | Real-world risk | Checkov | Prowler (default) | Prowler (full) | Fixed |
|---|---|---|---|---|---|---|
| 1 | Public S3 bucket (`Principal: "*"`, Block Public Access off) | Data exposed to the entire internet | Caught (6) | Caught (3) | Caught | ✅ |
| 2 | IAM user with `*:*` inline policy | Full account takeover if credentials leak | Caught (10) | Caught (8) | Caught | ✅ |
| 3 | Security group with SSH 22 / RDP 3389 open to `0.0.0.0/0` | Brute-force and remote access attacks | Caught | **Missed** | Caught | ✅ |
| 4 | Unencrypted EBS volume | Readable data if a volume or snapshot is copied | Caught | Caught | Caught | ✅ |
| 5 | No CloudTrail | No audit trail, so incidents can't be investigated | **Missed** | Caught (20) | Caught | ✅ |

### Detection gaps

- **Checkov cannot see absences.** CloudTrail was never written in the code, so there was nothing to fail. Only a live scan asking "is anything recording API activity?" finds it.
- **Prowler skips unused resources by default.** The open security group wasn't attached to anything, so the default scan only reported "security group not used" (Low). With `--scan-unused-services`, ports 22 and 3389 were flagged High. The same setting also hid the VPC default security group allowing traffic (CIS 5.4), and later hid three EC2/VPC checks during verification.
- **A clean-looking scan summary isn't proof.** A targeted re-check reported "0 failed, 2 passed" when five checks had been requested. Three had silently not run. Always confirm what was actually scanned.

---

## 4. Remediation

All fixes are in `terraform/main.tf`.

**Planted issues**
- S3: Block Public Access on (bucket and account level), public policy replaced with a deny-non-HTTPS policy, versioning and access logging enabled
- IAM: overprivileged user and wildcard policy deleted
- Network: security group inbound rules removed; default security group stripped of all rules
- EBS: volume replaced with an encrypted one (AWS cannot encrypt an existing volume in place); encryption by default enabled for the region
- CloudTrail: multi-region trail with log file validation, delivered to a locked-down log bucket and streamed to CloudWatch Logs

**Account baseline (never in the original code, found only by Prowler)**
- IAM password policy (14+ characters, complexity, reuse prevention, 90-day expiry)
- IAM Access Analyzer enabled
- Default network ACL restricted to VPC-internal inbound traffic
- 15 CIS metric filters and alarms (root usage, sign-in without MFA, IAM/network/S3/KMS/Config/Organizations changes, unauthorized API calls, and more) notifying via SNS email

**Round 2 (found only by the full after-scan)**
- CloudTrail service role: added `aws:SourceAccount` / `aws:SourceArn` conditions to prevent confused-deputy misuse
- EBS snapshot public sharing blocked account-wide
- IMDSv2 required by default for new EC2 instances (IMDSv1 was the vector in the 2019 Capital One breach)
- Automatic public IPs disabled on the three default subnets
- Organizations alarm pattern corrected: the first version listed 18 of the 21 events Prowler requires

**Verification after round 2:** all targeted checks PASS. CloudTrail confirmed still delivering to CloudWatch Logs after the trust-policy change (`LatestCloudWatchLogsDeliveryError: null`), proving the tightened permission didn't silently break monitoring.

---

## 5. Results

### Checkov (code)

| | Before | After |
|---|---|---|
| Passed | 11 | 60 |
| Failed | 30 | **0** |
| Skipped (documented accepted risks) | 0 | 17 |

Each skip is an inline comment, `#checkov:skip=<ID>:<reason>`, next to the resource it applies to.

### Prowler (live account)

| | Baseline (default scan) | After (full scan) | After round 2 |
|---|---|---|---|
| Scope | Used services only | All services | Targeted re-checks |
| Failed | 84 | 67 | **60** |
| Passed | 43 | 171 | – |
| Critical | 4 | 2 | 2 |

The scans had different scope, so the totals aren't directly comparable. The full scan evaluated services the baseline skipped (Athena, Glue, RDS, VPC), which added both passes and failures. Progress was measured **per finding**:

- **51 of 84** baseline findings resolved (50 in round 1, plus the Organizations alarm in round 2)
- **33** baseline findings remain, all accepted (section 6)
- **33** new findings appeared in the full scan: **6 fixed** in round 2, **27 accepted**

---

## 6. Accepted risks

Every open finding has a recorded reason. Main groups:

| Group | Examples | Reason |
|---|---|---|
| My own admin access (Critical ×2, High ×3) | `AdministratorAccess` on admin group; root and admin use virtual rather than hardware MFA; root used on scan day | A one-person lab needs one admin identity. MFA is enforced. Production: IAM Identity Center and hardware security keys. Root usage clears once root stays unused. |
| Customer-managed KMS keys | CloudTrail, log group, S3 buckets | AWS-managed encryption is on everywhere. Customer-managed keys cost about $1/month each with no lab benefit. Required in some compliance regimes. |
| SNS topic not KMS-encrypted | Alarm topic | **Deliberate:** CloudWatch alarms cannot publish to a topic encrypted with the AWS-managed SNS key. Following the scanner would silently break every alert. |
| Data durability controls | Replication, lifecycle, Object Lock, MFA Delete, backup plans, snapshots | Disaster-recovery and retention controls for data that doesn't exist in this lab. |
| Log bucket access logging | `cspm-lab-logs-*` | A log bucket logging to itself creates an infinite loop. |
| AWS Organizations (5) | SCPs, aggregators, tag policies | Multi-account governance; this is a standalone account. |
| Unused services (12) | Athena, Glue, RDS, Network Firewall, VPC endpoints, flow logs, Bedrock, SageMaker | No workloads use these services. AWS default settings flagged on unused services. |
| Other | AWS Config recorder, alternate contacts, CloudTrail Insights, S3 data events | Cost or out of scope for the lab; recommended for production. |

---

## 7. Lessons learned

1. **Use code scanning and live scanning together.** Each tool missed a planted issue the other caught.
2. **Check scanner coverage.** "0 findings" or a short passed list can mean the check never ran: the Prowler unused-services default here, and Trivy scanning zero files in my DevSecOps project.
3. **Finding count isn't risk count.** One missing CloudTrail produced 20 findings, and one wildcard policy produced 10 in Checkov. Triage by root cause.
4. **Read the plan before applying.** `terraform plan` revealed that changing a security group's description forces replacement, which would briefly disconnect attached servers in a real environment.
5. **Verify dependent systems after tightening permissions.** The CloudTrail role fix was confirmed against actual log delivery, not just the scanner.
6. **Scanners can be wrong for your context.** Encrypting the SNS topic with the default key, as Checkov suggests, would have broken alerting. Benchmarks also disagree with each other: CIS requires 90-day password expiry, while current NIST guidance advises against forced expiry.
7. **Short-lived credentials are worth the friction.** Expiring sessions interrupted the work several times, but nothing persistent ever sat on disk to leak.
8. **Fixing things surfaces new checks.** Creating CloudTrail enabled checks that hadn't run before (KMS, Insights, bucket MFA Delete). Remediation is iterative.

---

## 8. Evidence in this repository

| File | Contents |
|---|---|
| `terraform/main.tf` | Secure configuration; Git history contains the insecure version |
| `CHECKOV-TRIAGE.md` | 30 code findings grouped by root cause |
| `PROWLER-TRIAGE.md` | 84 baseline live findings grouped by root cause |
| `reports/checkov-before.txt`, `reports/checkov-after.txt` | Raw Checkov output |
| Raw Prowler output | Kept locally and excluded from Git (contains account identifiers) |
