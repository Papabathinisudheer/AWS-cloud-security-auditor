import boto3
import csv
from datetime import datetime
from botocore.exceptions import ClientError, NoCredentialsError


results = []


def add_result(resource, check, status, details):
    results.append({
        "Resource": resource,
        "Check": check,
        "Status": status,
        "Details": details
    })


def audit_s3(s3):
    print("\n[1] Auditing S3 Buckets...")

    try:
        buckets = s3.list_buckets()["Buckets"]

        for bucket in buckets:
            name = bucket["Name"]

            # Check public access block
            try:
                config = s3.get_public_access_block(
                    Bucket=name
                )["PublicAccessBlockConfiguration"]

                all_enabled = all([
                    config.get("BlockPublicAcls", False),
                    config.get("IgnorePublicAcls", False),
                    config.get("BlockPublicPolicy", False),
                    config.get("RestrictPublicBuckets", False)
                ])

                status = "PASS" if all_enabled else "WARNING"

                add_result(
                    name,
                    "S3 Public Access Block",
                    status,
                    "All public access block settings enabled"
                    if all_enabled else
                    "One or more public access block settings disabled"
                )

            except ClientError as e:
                add_result(
                    name,
                    "S3 Public Access Block",
                    "WARNING",
                    e.response["Error"]["Code"]
                )

            # Check encryption
            try:
                s3.get_bucket_encryption(Bucket=name)

                add_result(
                    name,
                    "S3 Encryption",
                    "PASS",
                    "Default encryption configured"
                )

            except ClientError as e:
                code = e.response["Error"]["Code"]

                if code == "ServerSideEncryptionConfigurationNotFoundError":
                    add_result(
                        name,
                        "S3 Encryption",
                        "WARNING",
                        "Default encryption not configured"
                    )
                else:
                    add_result(
                        name,
                        "S3 Encryption",
                        "ERROR",
                        code
                    )

            # Check versioning
            try:
                versioning = s3.get_bucket_versioning(
                    Bucket=name
                ).get("Status")

                status = (
                    "PASS"
                    if versioning == "Enabled"
                    else "WARNING"
                )

                add_result(
                    name,
                    "S3 Versioning",
                    status,
                    f"Versioning status: {versioning or 'Disabled'}"
                )

            except ClientError as e:
                add_result(
                    name,
                    "S3 Versioning",
                    "ERROR",
                    e.response["Error"]["Code"]
                )

    except ClientError as e:
        print("S3 audit failed:", e.response["Error"]["Code"])


def audit_iam(iam):
    print("\n[2] Auditing IAM Users...")

    try:
        paginator = iam.get_paginator("list_users")

        for page in paginator.paginate():
            for user in page["Users"]:
                username = user["UserName"]

                mfa = iam.list_mfa_devices(
                    UserName=username
                )["MFADevices"]

                status = "PASS" if mfa else "WARNING"

                add_result(
                    username,
                    "IAM MFA Check",
                    status,
                    "MFA enabled" if mfa else "MFA not enabled"
                )

    except ClientError as e:
        print("IAM audit failed:", e.response["Error"]["Code"])


def audit_security_groups(ec2):
    print("\n[3] Auditing Security Groups...")

    risky_ports = {
        22: "SSH",
        23: "Telnet",
        3389: "RDP",
        3306: "MySQL",
        5432: "PostgreSQL"
    }

    try:
        groups = ec2.describe_security_groups()["SecurityGroups"]

        for group in groups:
            group_id = group["GroupId"]

            for rule in group["IpPermissions"]:
                from_port = rule.get("FromPort")
                to_port = rule.get("ToPort")

                if from_port is None:
                    continue

                for ip_range in rule.get("IpRanges", []):
                    cidr = ip_range.get("CidrIp", "")

                    if cidr == "0.0.0.0/0":
                        for port, service in risky_ports.items():

                            if from_port <= port <= to_port:
                                add_result(
                                    group_id,
                                    f"Risky Port: {service} ({port})",
                                    "WARNING",
                                    f"Port exposed to {cidr}"
                                )

    except ClientError as e:
        print(
            "Security Group audit failed:",
            e.response["Error"]["Code"]
        )


def generate_report():
    filename = (
        "aws_security_report_"
        + datetime.now().strftime("%Y%m%d_%H%M%S")
        + ".csv"
    )

    with open(filename, "w", newline="") as file:
        writer = csv.DictWriter(
            file,
            fieldnames=[
                "Resource",
                "Check",
                "Status",
                "Details"
            ]
        )

        writer.writeheader()
        writer.writerows(results)

    print("\nReport generated:", filename)


def main():
    print("=" * 50)
    print("       AWS CLOUD SECURITY AUDITOR")
    print("=" * 50)

    try:
        session = boto3.Session()

        s3 = session.client("s3")
        iam = session.client("iam")
        ec2 = session.client("ec2")

        audit_s3(s3)
        audit_iam(iam)
        audit_security_groups(ec2)

        print("\n========== AUDIT RESULTS ==========")

        for item in results:
            print(
                f"[{item['Status']}] "
                f"{item['Resource']} | "
                f"{item['Check']} | "
                f"{item['Details']}"
            )

        generate_report()

        print("\nAudit completed successfully.")

    except NoCredentialsError:
        print("\nAWS credentials not found.")
        print("Configure AWS CLI credentials first.")

    except ClientError as e:
        print("\nAWS Error:", e.response["Error"]["Code"])


if __name__ == "__main__":
    main()
