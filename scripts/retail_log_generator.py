"""
RetailShield — Synthetic Retail Log Generator
ShieldTech Ltd | Tanvir Farhad | 2026
github.com/TFT444/RetailShield

Generates realistic retail environment logs and ships them to a
Microsoft Sentinel Log Analytics workspace via the Logs Ingestion API.

Usage:
  pip install requests faker
  python retail_log_generator.py --mode normal
  python retail_log_generator.py --mode attack
  python retail_log_generator.py --mode mixed
  python retail_log_generator.py --dry-run
"""

import argparse
import json
import random
import hashlib
import hmac
import base64
import datetime
import requests
from faker import Faker

fake = Faker("en_GB")

WORKSPACE_ID = "YOUR_WORKSPACE_ID"
SHARED_KEY = "YOUR_SHARED_KEY"
LOG_TYPE = "RetailShield_Logs"
API_VERSION = "2016-04-01"

STORES = [
    {"id": "STORE-001", "name": "Hounslow Branch"},
    {"id": "STORE-002", "name": "Hammersmith Branch"},
    {"id": "STORE-003", "name": "Ealing Branch"},
]

STAFF = [
    {"id": "EMP001", "name": "James Carter",   "role": "BOH Manager",     "shift_start": 9,  "shift_end": 17},  # noqa: E501
    {"id": "EMP002", "name": "Sarah Mitchell", "role": "Sales Associate", "shift_start": 12, "shift_end": 20},  # noqa: E501
    {"id": "EMP003", "name": "Omar Hussain",   "role": "Store Manager",   "shift_start": 8,  "shift_end": 16},  # noqa: E501
    {"id": "EMP004", "name": "Priya Patel",    "role": "BOH Associate",   "shift_start": 6,  "shift_end": 14},  # noqa: E501
]

TERMINALS = ["POS-001", "POS-002", "POS-003", "POS-004"]

PRODUCTS = [
    {"sku": "NK-001", "name": "Nike Air Max 270", "price": 145.00},
    {"sku": "NK-002", "name": "Nike React Miler", "price": 110.00},
    {"sku": "AD-001", "name": "Adidas Ultraboost", "price": 175.00},
]

MALICIOUS_IPS = ["185.220.101.47", "172.16.0.45", "203.45.12.88", "91.234.55.12"]
PHISHING_DOMAINS = ["supplier-invoices@dr4gonmail.com", "payroll-update@hrnike-secure.net"]


def now_iso():
    return datetime.datetime.utcnow().isoformat() + "Z"


def random_staff():
    return random.choice(STAFF)


def random_bad_ip():
    return random.choice(MALICIOUS_IPS)


def gen_pos_transaction():
    staff = random_staff()
    product = random.choice(PRODUCTS)
    return {
        "EventType": "POS_Transaction",
        "TimeGenerated": now_iso(),
        "StoreID": random.choice(STORES)["id"],
        "TerminalID": random.choice(TERMINALS),
        "OperatorID": staff["id"],
        "OperatorName": staff["name"],
        "TransactionType": random.choices(["SALE", "REFUND", "VOID"], weights=[75, 15, 10])[0],
        "ProductSKU": product["sku"],
        "TotalAmount": round(product["price"] * random.randint(1, 3), 2),
        "PaymentMethod": random.choice(["CARD", "CASH", "CONTACTLESS"]),
        "SuspicionScore": 0,
        "Severity": "INFO",
        "Category": "Normal_Transaction",
    }


def gen_phishing_email():
    staff = random_staff()
    return {
        "EventType": "Email_Event",
        "TimeGenerated": now_iso(),
        "SenderAddress": random.choice(PHISHING_DOMAINS),
        "RecipientName": staff["name"],
        "Subject": "URGENT: Invoice overdue - immediate action required",
        "HasAttachment": True,
        "AttachmentType": random.choice(["exe", "docm", "zip"]),
        "PhishingScore": random.randint(80, 99),
        "SuspicionScore": 90,
        "MITRETechnique": "T1566.001",
        "MITRETactic": "Initial Access",
        "Severity": "HIGH",
        "Category": "Phishing_Detected",
    }


def gen_credential_stuffing():
    return {
        "EventType": "Credential_Stuffing",
        "TimeGenerated": now_iso(),
        "SourceIP": random_bad_ip(),
        "TargetSystem": "POS_Admin",
        "FailedAttempts": random.randint(50, 300),
        "GeoLocation": random.choice(["Russia", "Vietnam", "China"]),
        "SuspicionScore": 90,
        "MITRETechnique": "T1110.004",
        "MITRETactic": "Credential Access",
        "Severity": "HIGH",
        "Category": "Credential_Stuffing",
    }


def gen_ransomware_indicator():
    return {
        "EventType": "Ransomware_Indicator",
        "TimeGenerated": now_iso(),
        "DeviceName": "WORKSTATION-" + str(random.randint(1, 20)),
        "FilesModified": random.randint(150, 800),
        "SuspiciousExtension": random.choice([".encrypted", ".locked", ".dragon"]),
        "ShadowCopyDeleted": True,
        "C2IP": random_bad_ip(),
        "RansomwareFamily": random.choice(["DragonForce", "LockBit", "BlackCat"]),
        "SuspicionScore": 99,
        "MITRETechnique": "T1486",
        "MITRETactic": "Impact",
        "Severity": "CRITICAL",
        "Category": "Ransomware_Indicator",
    }


def gen_data_exfiltration():
    return {
        "EventType": "Data_Exfiltration",
        "TimeGenerated": now_iso(),
        "SourceUser": random_staff()["name"],
        "DestinationIP": random_bad_ip(),
        "DataTransferredMB": round(random.uniform(500, 3000), 1),
        "DestinationPort": random.choice([4444, 8080, 1337]),
        "SystemSource": "Customer_Database",
        "GeoDestination": random.choice(["Russia", "China", "Unknown"]),
        "SuspicionScore": 95,
        "MITRETechnique": "T1048",
        "MITRETactic": "Exfiltration",
        "Severity": "CRITICAL",
        "Category": "Data_Exfiltration",
    }


def gen_ai_voice_fraud():
    staff = random_staff()
    return {
        "EventType": "AI_Voice_Fraud",
        "TimeGenerated": now_iso(),
        "TargetEmployee": staff["name"],
        "AIConfidenceScore": round(random.uniform(0.87, 0.99), 2),
        "ImpersonatingEntity": random.choice(["Area Manager", "Head Office", "DHL"]),
        "RequestMade": "Delivery redirect to alternative address",
        "SuspicionScore": 94,
        "MITRETechnique": "T1598",
        "MITRETactic": "Social Engineering",
        "Severity": "CRITICAL",
        "Category": "AI_Voice_Deepfake",
    }


def send_to_sentinel(logs, dry_run=False):
    if dry_run or WORKSPACE_ID == "YOUR_WORKSPACE_ID":
        print(f"[DRY RUN] {len(logs)} logs generated")
        for log in logs[:3]:
            print(json.dumps(log, indent=2))
        return True

    body = json.dumps(logs)
    rfc1123date = datetime.datetime.utcnow().strftime("%a, %d %b %Y %H:%M:%S GMT")
    content_length = len(body)
    x_headers = "x-ms-date:" + rfc1123date
    string_to_hash = "\n".join(
        ["POST", str(content_length), "application/json", x_headers, "/api/logs"]
    )
    decoded_key = base64.b64decode(SHARED_KEY)
    encoded_hash = base64.b64encode(
        hmac.new(decoded_key, string_to_hash.encode("utf-8"), digestmod=hashlib.sha256).digest()
    ).decode("utf-8")
    signature = f"SharedKey {WORKSPACE_ID}:{encoded_hash}"
    uri = (
        f"https://{WORKSPACE_ID}.ods.opinsights.azure.com"
        f"/api/logs?api-version={API_VERSION}"
    )
    headers = {
        "Content-Type": "application/json",
        "Authorization": signature,
        "Log-Type": LOG_TYPE,
        "x-ms-date": rfc1123date,
    }
    response = requests.post(uri, data=body, headers=headers)
    print(f"Sent {len(logs)} logs — Status: {response.status_code}")
    return response.status_code == 200


def main():
    parser = argparse.ArgumentParser(description="RetailShield Log Generator")
    parser.add_argument("--mode", choices=["normal", "attack", "mixed"], default="mixed")
    parser.add_argument("--count", type=int, default=100)
    parser.add_argument("--dry-run", action="store_true")
    args = parser.parse_args()

    print("RetailShield Log Generator — ShieldTech Ltd")
    print(f"Mode: {args.mode} | Count: {args.count} | Dry run: {args.dry_run}")

    logs = []
    if args.mode == "normal":
        logs = [gen_pos_transaction() for _ in range(args.count)]
    elif args.mode == "attack":
        logs = [
            gen_phishing_email(),
            gen_credential_stuffing(),
            gen_ransomware_indicator(),
            gen_data_exfiltration(),
            gen_ai_voice_fraud(),
        ]
    else:
        normal = [gen_pos_transaction() for _ in range(int(args.count * 0.8))]
        attacks = [
            gen_phishing_email(),
            gen_credential_stuffing(),
            gen_ransomware_indicator(),
            gen_data_exfiltration(),
            gen_ai_voice_fraud(),
        ]
        logs = normal + attacks
        random.shuffle(logs)

    send_to_sentinel(logs, dry_run=args.dry_run)
    print("Done!")


if __name__ == "__main__":
    main()
