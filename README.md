# AWS Cloud Security Auditor

## Project Overview
A Python-based cloud security auditing tool designed
to identify selected security misconfigurations
in Amazon Web Services (AWS).

## Features
- S3 Public Access Block Audit
- S3 Encryption Audit
- S3 Bucket Versioning Audit
- IAM User MFA Audit
- Security Group Risky Port Audit
- CSV Security Audit Report

## Technologies
- Python 3
- AWS
- Boto3
- AWS IAM
- Amazon S3
- Amazon EC2

## Installation

Install Python 3 and AWS CLI.

Install dependencies:

pip3 install -r requirements.txt

Configure AWS credentials:

aws configure

Run the project:

python3 cloud_auditor.py

## Output
The tool displays audit findings in the terminal
and generates a CSV report.

## Security
This project performs read-only auditing.
It does not modify AWS resources.

Use only AWS accounts that you own
or are authorized to audit.

## Author
Papabathini venkata sudheer

## Disclaimer
This is an educational cybersecurity project.
It is not a complete AWS compliance scanner.
