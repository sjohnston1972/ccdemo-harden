"""
email_latest_report.py - Find and email the latest audit report files
without running a new audit.

Usage:
    python email_latest_report.py
    python email_latest_report.py --dir /path/to/reports
    python email_latest_report.py --verbose
"""

import os
import re
import sys
import glob
import logging
import argparse
import smtplib
from datetime import datetime
from email import encoders
from email.mime.base import MIMEBase
from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
from dotenv import load_dotenv

load_dotenv()

# Timestamp pattern used in all audit filenames: YYYYMMDD_HHMMSS
TIMESTAMP_RE = re.compile(r'(\d{8}_\d{6})')

# All file patterns that constitute a full audit set
FILE_PATTERNS = [
    'audit_report_*.json',
    'AUDIT_SUMMARY_*.md',
    'PRE_DEPLOYMENT_CHECKLIST_*.md',
    'remediation_commands_*.txt',
]


def find_latest_audit_files(search_dir):
    """
    Scan search_dir for audit files, group them by timestamp,
    and return the files belonging to the most recent timestamp.
    """
    # Map timestamp -> list of file paths
    by_timestamp = {}

    for pattern in FILE_PATTERNS:
        for path in glob.glob(os.path.join(search_dir, pattern)):
            basename = os.path.basename(path)
            match = TIMESTAMP_RE.search(basename)
            if match:
                ts = match.group(1)
                by_timestamp.setdefault(ts, []).append(path)

    if not by_timestamp:
        return None, None

    latest_ts = sorted(by_timestamp.keys())[-1]
    return latest_ts, by_timestamp[latest_ts]


def format_timestamp(ts):
    """Convert YYYYMMDD_HHMMSS to a readable string."""
    try:
        dt = datetime.strptime(ts, '%Y%m%d_%H%M%S')
        return dt.strftime('%Y-%m-%d %H:%M:%S')
    except ValueError:
        return ts


def send_email(files, timestamp, verbose=False):
    """Send the given files as email attachments."""
    smtp_server   = os.getenv('SMTP_SERVER')
    smtp_port     = int(os.getenv('SMTP_PORT', 587))
    sender_email  = os.getenv('SENDER_EMAIL')
    sender_pass   = os.getenv('SENDER_PASSWORD')
    recipient     = os.getenv('RECIPIENT_EMAIL')
    sender_name   = os.getenv('SENDER_NAME', 'Network Audit')

    missing = [v for k, v in {
        'SMTP_SERVER': smtp_server,
        'SENDER_EMAIL': sender_email,
        'SENDER_PASSWORD': sender_pass,
        'RECIPIENT_EMAIL': recipient,
    }.items() if not v]

    if missing:
        print(f"ERROR: Missing email config in .env: {', '.join(missing)}")
        return False

    msg = MIMEMultipart()
    msg['From']    = f"{sender_name} <{sender_email}>"
    msg['To']      = recipient
    msg['Subject'] = f"Network Security Audit Report - {format_timestamp(timestamp)}"

    # Summarise what's attached in the body
    file_list = '\n'.join(f"  - {os.path.basename(f)}" for f in sorted(files))
    body = (
        f"Please find attached the latest network security audit report.\n\n"
        f"Audit timestamp: {format_timestamp(timestamp)}\n"
        f"Files attached ({len(files)}):\n{file_list}\n\n"
        f"-- Sent by email_latest_report.py"
    )
    msg.attach(MIMEText(body, 'plain'))

    # Attach each file
    for file_path in sorted(files):
        if not os.path.exists(file_path):
            print(f"WARNING: File not found, skipping: {file_path}")
            continue
        with open(file_path, 'rb') as f:
            part = MIMEBase('application', 'octet-stream')
            part.set_payload(f.read())
        encoders.encode_base64(part)
        part.add_header(
            'Content-Disposition',
            f'attachment; filename="{os.path.basename(file_path)}"'
        )
        msg.attach(part)
        if verbose:
            print(f"  Attached: {os.path.basename(file_path)}")

    print(f"Connecting to {smtp_server}:{smtp_port}...")
    try:
        with smtplib.SMTP(smtp_server, smtp_port) as server:
            server.starttls()
            server.login(sender_email, sender_pass)
            server.send_message(msg)
        print(f"Email sent successfully to: {recipient}")
        return True
    except smtplib.SMTPAuthenticationError:
        print("ERROR: SMTP authentication failed - check SENDER_EMAIL and SENDER_PASSWORD in .env")
        return False
    except Exception as e:
        print(f"ERROR: Failed to send email: {e}")
        logging.error("Email send failed", exc_info=True)
        return False


def main():
    parser = argparse.ArgumentParser(
        description='Email the latest audit report files without running a new audit.'
    )
    parser.add_argument(
        '--dir', '-d', default='.',
        help='Directory to search for audit files (default: current directory)'
    )
    parser.add_argument(
        '--verbose', '-v', action='store_true',
        help='Show each file as it is attached'
    )
    args = parser.parse_args()

    search_dir = os.path.abspath(args.dir)
    print(f"Searching for latest audit files in: {search_dir}")

    timestamp, files = find_latest_audit_files(search_dir)

    if not files:
        print("ERROR: No audit files with timestamps found. Run cisco_audit.py first.")
        sys.exit(1)

    print(f"Latest audit timestamp: {format_timestamp(timestamp)}")
    print(f"Files found ({len(files)}):")
    for f in sorted(files):
        print(f"  {os.path.basename(f)}")

    print()
    success = send_email(files, timestamp, verbose=args.verbose)
    sys.exit(0 if success else 1)


if __name__ == '__main__':
    main()
