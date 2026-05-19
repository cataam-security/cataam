#!/usr/bin/env python3
"""
AWS Cloud Posture Check — audits an AWS account against CIS AWS Foundations Benchmark v1.5.
Maps findings to CIS controls, SOC 2 CC6, and ISO 27001 Annex A.
Exports Cataam-importable JSON.

Usage:
    python cloud-posture-check.py --profile prod-readonly --output aws-posture.json
    python cloud-posture-check.py --section iam --output iam-findings.json
"""

import argparse
import json
import sys
from datetime import datetime, timezone

try:
    import boto3
    from botocore.exceptions import ClientError, NoCredentialsError
except ImportError:
    print("boto3 is required: pip install boto3")
    sys.exit(1)

try:
    from rich.console import Console
    from rich.table import Table
    HAS_RICH = True
except ImportError:
    HAS_RICH = False

TOOL_VERSION = "1.1.0"
CATAAM_IMPORT_VERSION = "1.0"

console = Console() if HAS_RICH else None

def cprint(msg, style=""):
    if console:
        console.print(msg if not style else f"[{style}]{msg}[/{style}]")
    else:
        print(msg)


class Finding:
    def __init__(self, control, section, title, status, detail="", severity="MEDIUM",
                 resource="", iso27001="", soc2=""):
        self.control   = control
        self.section   = section
        self.title     = title
        self.status    = status      # PASS | FAIL | WARN | NA
        self.detail    = detail
        self.severity  = severity
        self.resource  = resource
        self.iso27001  = iso27001
        self.soc2      = soc2

    def to_dict(self):
        return {
            "control":   self.control,
            "section":   self.section,
            "title":     self.title,
            "status":    self.status,
            "severity":  self.severity,
            "detail":    self.detail,
            "resource":  self.resource,
            "iso27001":  self.iso27001,
            "soc2":      self.soc2,
            "cataam_tags": [f"severity:{self.severity.lower()}", f"cis:{self.control}", "source:aws"],
        }


findings: list[Finding] = []


def add(control, section, title, status, detail="", severity="MEDIUM",
        resource="", iso27001="A.9.2", soc2="CC6.1"):
    f = Finding(control, section, title, status, detail, severity, resource, iso27001, soc2)
    findings.append(f)
    color_map = {"PASS": "green", "FAIL": "red", "WARN": "yellow", "NA": "dim"}
    color = color_map.get(status, "white")
    cprint(f"[{color}][{status}][/{color}] [{control}] {title}")
    if detail:
        cprint(f"       {detail}", "dim")


# ── IAM Checks (CIS Section 1) ────────────────────────────────────────────────

def check_iam(session):
    cprint("\n=== Section 1: Identity and Access Management ===", "bold blue")
    iam = session.client("iam")

    # 1.1 — Root account MFA
    try:
        summary = iam.get_account_summary()["SummaryMap"]
        if summary.get("AccountMFAEnabled", 0) == 1:
            add("1.1", "iam", "Ensure MFA is enabled for the root account", "PASS",
                iso27001="A.9.4", soc2="CC6.1")
        else:
            add("1.1", "iam", "Ensure MFA is enabled for the root account", "FAIL",
                "Root account does not have MFA enabled", "CRITICAL",
                iso27001="A.9.4", soc2="CC6.1")
    except ClientError as e:
        add("1.1", "iam", "Ensure MFA is enabled for the root account", "WARN", str(e))

    # 1.2 — No root access keys
    try:
        resp = iam.get_account_summary()["SummaryMap"]
        if resp.get("AccountAccessKeysPresent", 0) == 0:
            add("1.2", "iam", "Ensure no root account access keys exist", "PASS",
                iso27001="A.9.2", soc2="CC6.1")
        else:
            add("1.2", "iam", "Ensure no root account access keys exist", "FAIL",
                "Root account has active access keys — remove immediately", "CRITICAL",
                iso27001="A.9.2", soc2="CC6.1")
    except ClientError as e:
        add("1.2", "iam", "Ensure no root account access keys exist", "WARN", str(e))

    # 1.3 — MFA for all IAM users with console access
    try:
        paginator = iam.get_paginator("list_users")
        users_without_mfa = []
        for page in paginator.paginate():
            for user in page["Users"]:
                login_profile = None
                try:
                    iam.get_login_profile(UserName=user["UserName"])
                    login_profile = True
                except ClientError:
                    pass
                if login_profile:
                    mfa = iam.list_mfa_devices(UserName=user["UserName"])
                    if not mfa["MFADevices"]:
                        users_without_mfa.append(user["UserName"])

        if not users_without_mfa:
            add("1.3", "iam", "Ensure MFA is enabled for all IAM users with console access", "PASS",
                iso27001="A.9.4", soc2="CC6.1")
        else:
            add("1.3", "iam", "Ensure MFA is enabled for all IAM users with console access", "FAIL",
                f"Users without MFA: {', '.join(users_without_mfa[:10])}", "HIGH",
                iso27001="A.9.4", soc2="CC6.1")
    except ClientError as e:
        add("1.3", "iam", "Ensure MFA is enabled for all IAM users with console access", "WARN", str(e))

    # 1.4 — Password policy
    try:
        policy = iam.get_account_password_policy()["PasswordPolicy"]
        checks = [
            ("MinimumPasswordLength",         14,    "Minimum password length >= 14"),
            ("RequireUppercaseCharacters",     True,  "Require uppercase characters"),
            ("RequireLowercaseCharacters",     True,  "Require lowercase characters"),
            ("RequireNumbers",                 True,  "Require numbers"),
            ("RequireSymbols",                 True,  "Require symbols"),
            ("MaxPasswordAge",                 90,    "Max password age <= 90 days"),
            ("PasswordReusePrevention",        24,    "Password reuse prevention >= 24"),
        ]
        for key, threshold, desc in checks:
            val = policy.get(key, 0 if isinstance(threshold, int) else False)
            ok = (val >= threshold) if isinstance(threshold, int) else (val == threshold)
            add(f"1.4.{key}", "iam", f"Password policy: {desc}",
                "PASS" if ok else "FAIL",
                f"Current: {val}" if not ok else "",
                "MEDIUM" if ok else "HIGH",
                iso27001="A.9.4", soc2="CC6.1")
    except ClientError:
        add("1.4", "iam", "Ensure IAM password policy is configured", "FAIL",
            "No password policy is set", "HIGH", iso27001="A.9.4", soc2="CC6.1")

    # 1.5 — No inline policies on users (use groups/roles)
    try:
        paginator = iam.get_paginator("list_users")
        users_with_inline = []
        for page in paginator.paginate():
            for user in page["Users"]:
                inline = iam.list_user_policies(UserName=user["UserName"])
                if inline["PolicyNames"]:
                    users_with_inline.append(user["UserName"])
        if not users_with_inline:
            add("1.5", "iam", "Ensure IAM policies are attached to groups or roles only", "PASS",
                iso27001="A.9.2", soc2="CC6.3")
        else:
            add("1.5", "iam", "Ensure IAM policies are attached to groups or roles only", "FAIL",
                f"Users with inline policies: {', '.join(users_with_inline[:10])}", "MEDIUM",
                iso27001="A.9.2", soc2="CC6.3")
    except ClientError as e:
        add("1.5", "iam", "Ensure IAM policies are attached to groups or roles only", "WARN", str(e))


# ── S3 Checks (CIS Section 2) ─────────────────────────────────────────────────

def check_storage(session):
    cprint("\n=== Section 2: Storage ===" , "bold blue")
    s3 = session.client("s3")

    try:
        buckets = s3.list_buckets().get("Buckets", [])
    except ClientError as e:
        add("2.1", "storage", "S3 bucket checks", "WARN", str(e))
        return

    for bucket in buckets:
        name = bucket["Name"]

        # 2.1.1 — Block public access
        try:
            bpa = s3.get_public_access_block(Bucket=name)["PublicAccessBlockConfiguration"]
            if all(bpa.get(k, False) for k in [
                "BlockPublicAcls", "IgnorePublicAcls",
                "BlockPublicPolicy", "RestrictPublicBuckets"
            ]):
                add("2.1.1", "storage", f"S3 bucket public access blocked: {name}", "PASS",
                    resource=f"arn:aws:s3:::{name}", iso27001="A.8.3", soc2="CC6.1")
            else:
                add("2.1.1", "storage", f"S3 bucket public access blocked: {name}", "FAIL",
                    f"Bucket {name} has public access enabled", "HIGH",
                    resource=f"arn:aws:s3:::{name}", iso27001="A.8.3", soc2="CC6.1")
        except ClientError:
            add("2.1.1", "storage", f"S3 bucket public access blocked: {name}", "WARN",
                f"Could not retrieve public access block config for {name}")

        # 2.1.2 — Server-side encryption
        try:
            enc = s3.get_bucket_encryption(Bucket=name)
            rules = enc["ServerSideEncryptionConfiguration"]["Rules"]
            if rules:
                add("2.1.2", "storage", f"S3 bucket encryption enabled: {name}", "PASS",
                    resource=f"arn:aws:s3:::{name}", iso27001="A.8.24", soc2="CC6.7")
            else:
                add("2.1.2", "storage", f"S3 bucket encryption enabled: {name}", "FAIL",
                    f"No SSE configured on {name}", "HIGH",
                    resource=f"arn:aws:s3:::{name}", iso27001="A.8.24", soc2="CC6.7")
        except ClientError:
            add("2.1.2", "storage", f"S3 bucket encryption enabled: {name}", "FAIL",
                f"No SSE configured on {name}", "HIGH",
                resource=f"arn:aws:s3:::{name}", iso27001="A.8.24", soc2="CC6.7")


# ── Logging Checks (CIS Section 3) ────────────────────────────────────────────

def check_logging(session, region):
    cprint("\n=== Section 3: Logging ===" , "bold blue")

    # 3.1 — CloudTrail enabled
    ct = session.client("cloudtrail", region_name=region)
    try:
        trails = ct.describe_trails(includeShadowTrails=False).get("trailList", [])
        multi_region = [t for t in trails if t.get("IsMultiRegionTrail")]
        if multi_region:
            add("3.1", "logging", "Ensure CloudTrail is enabled in all regions", "PASS",
                iso27001="A.8.15", soc2="CC7.2")
        else:
            add("3.1", "logging", "Ensure CloudTrail is enabled in all regions", "FAIL",
                "No multi-region CloudTrail trail found", "HIGH",
                iso27001="A.8.15", soc2="CC7.2")

        # 3.2 — CloudTrail log file validation
        for trail in trails:
            if trail.get("LogFileValidationEnabled"):
                add("3.2", "logging",
                    f"CloudTrail log file validation enabled: {trail['Name']}", "PASS",
                    resource=trail.get("TrailARN", ""), iso27001="A.8.15", soc2="CC7.2")
            else:
                add("3.2", "logging",
                    f"CloudTrail log file validation enabled: {trail['Name']}", "FAIL",
                    f"Trail {trail['Name']} does not have log file validation", "MEDIUM",
                    resource=trail.get("TrailARN", ""), iso27001="A.8.15", soc2="CC7.2")

    except ClientError as e:
        add("3.1", "logging", "Ensure CloudTrail is enabled", "WARN", str(e))

    # 3.3 — VPC Flow Logs
    ec2 = session.client("ec2", region_name=region)
    try:
        vpcs = ec2.describe_vpcs().get("Vpcs", [])
        flow_logs = ec2.describe_flow_logs().get("FlowLogs", [])
        vpc_ids_with_logs = {fl["ResourceId"] for fl in flow_logs}
        for vpc in vpcs:
            vpc_id = vpc["VpcId"]
            if vpc_id in vpc_ids_with_logs:
                add("3.3", "logging", f"VPC Flow Logs enabled: {vpc_id}", "PASS",
                    resource=vpc_id, iso27001="A.8.15", soc2="CC7.2")
            else:
                add("3.3", "logging", f"VPC Flow Logs enabled: {vpc_id}", "FAIL",
                    f"VPC {vpc_id} does not have flow logs enabled", "MEDIUM",
                    resource=vpc_id, iso27001="A.8.15", soc2="CC7.2")
    except ClientError as e:
        add("3.3", "logging", "VPC Flow Logs check", "WARN", str(e))


# ── Networking Checks (CIS Section 4) ─────────────────────────────────────────

def check_networking(session, region):
    cprint("\n=== Section 4: Networking ===" , "bold blue")
    ec2 = session.client("ec2", region_name=region)

    # 4.1 — No security groups allow 0.0.0.0/0 on SSH (port 22)
    try:
        sgs = ec2.describe_security_groups().get("SecurityGroups", [])
        for sg in sgs:
            sg_id   = sg["GroupId"]
            sg_name = sg.get("GroupName", sg_id)
            for rule in sg.get("IpPermissions", []):
                from_port = rule.get("FromPort", 0)
                to_port   = rule.get("ToPort",   65535)
                for cidr_range in rule.get("IpRanges", []):
                    if cidr_range.get("CidrIp") == "0.0.0.0/0":
                        if from_port <= 22 <= to_port:
                            add("4.1", "networking",
                                f"No unrestricted SSH (0.0.0.0/0) on port 22: {sg_name}", "FAIL",
                                f"Security group {sg_id} allows SSH from 0.0.0.0/0", "HIGH",
                                resource=sg_id, iso27001="A.8.20", soc2="CC6.6")
                        elif from_port <= 3389 <= to_port:
                            add("4.2", "networking",
                                f"No unrestricted RDP (0.0.0.0/0) on port 3389: {sg_name}", "FAIL",
                                f"Security group {sg_id} allows RDP from 0.0.0.0/0", "HIGH",
                                resource=sg_id, iso27001="A.8.20", soc2="CC6.6")
    except ClientError as e:
        add("4.1", "networking", "Security group checks", "WARN", str(e))


# ── Output ─────────────────────────────────────────────────────────────────────

def write_cataam_json(output_path: str, profile: str, region: str):
    total = len(findings)
    pass_  = sum(1 for f in findings if f.status == "PASS")
    fail_  = sum(1 for f in findings if f.status == "FAIL")
    warn_  = sum(1 for f in findings if f.status == "WARN")

    payload = {
        "cataam_import_version": CATAAM_IMPORT_VERSION,
        "tool": "cloud-posture-check",
        "tool_version": TOOL_VERSION,
        "framework": "CIS AWS Foundations Benchmark v1.5",
        "scan_timestamp": datetime.now(timezone.utc).isoformat(),
        "target": {"aws_profile": profile, "region": region},
        "summary": {"total": total, "pass": pass_, "fail": fail_, "warn": warn_,
                    "score_pct": round(pass_ * 100 / max(total, 1))},
        "frameworks": ["CIS AWS Foundations Benchmark v1.5", "ISO 27001:2022", "SOC 2 Type II"],
        "findings": [f.to_dict() for f in findings],
    }

    with open(output_path, "w") as fh:
        json.dump(payload, fh, indent=2)
    cprint(f"\nCataam JSON written to {output_path}", "green")
    cprint("Import at: https://cataam.com/import", "dim")


def main():
    parser = argparse.ArgumentParser(description="Cataam AWS Cloud Posture Check (CIS AWS v1.5)")
    parser.add_argument("--profile", default="default", help="AWS CLI profile")
    parser.add_argument("--region",  default="us-east-1", help="AWS region")
    parser.add_argument("--output",  default="",    help="Cataam-importable JSON output file")
    parser.add_argument("--section", default="all",
                        choices=["all", "iam", "storage", "logging", "networking"],
                        help="Run only a specific section")
    args = parser.parse_args()

    cprint("=" * 56, "bold")
    cprint(f" Cataam AWS Cloud Posture Check v{TOOL_VERSION}", "bold")
    cprint(f" Profile: {args.profile} | Region: {args.region}", "dim")
    cprint("=" * 56, "bold")

    try:
        session = boto3.Session(profile_name=args.profile, region_name=args.region)
        sts = session.client("sts")
        identity = sts.get_caller_identity()
        cprint(f" Account: {identity['Account']} | ARN: {identity['Arn']}", "dim")
    except NoCredentialsError:
        cprint("No AWS credentials found. Configure with 'aws configure' or set environment variables.", "red")
        sys.exit(1)
    except ClientError as e:
        cprint(f"AWS authentication error: {e}", "red")
        sys.exit(1)

    sections = args.section
    if sections in ("all", "iam"):
        check_iam(session)
    if sections in ("all", "storage"):
        check_storage(session)
    if sections in ("all", "logging"):
        check_logging(session, args.region)
    if sections in ("all", "networking"):
        check_networking(session, args.region)

    total = len(findings)
    pass_ = sum(1 for f in findings if f.status == "PASS")
    fail_ = sum(1 for f in findings if f.status == "FAIL")
    cprint(f"\n{'='*56}", "bold")
    cprint(f" SUMMARY: {pass_}/{total} checks passed | {fail_} failed", "bold")
    cprint("=" * 56, "bold")

    if args.output:
        write_cataam_json(args.output, args.profile, args.region)


if __name__ == "__main__":
    main()
