# Secure Cloud-Based Question Paper Management System

A simple Python Flask project based on the five-tier architecture in the supplied diagram.

> **Important:** This is an academic/demo implementation. It demonstrates the architecture concepts locally; it is not a production cloud security system.

## Architecture mapping

| Diagram tier | Simple implementation |
|---|---|
| Tier 1 - User Access | Flask login, role-based access, demo MFA |
| Tier 2 - Network Security | WAF-style input checks and API Gateway-style API routes |
| Tier 3 - Application | Dynamic encryption engine and subject-based sharding |
| Tier 4 - Data & Key Management | Local KMS simulation using a Fernet key + two encrypted JSON shards |
| Tier 5 - Monitoring & Audit | Append-only audit log + SIEM dashboard |

## Features

- Question Setter and Administrator roles
- Demo MFA using a 6-digit OTP
- Add question papers/questions
- AES-style authenticated encryption through Python `cryptography`/Fernet
- Two logical encrypted shards
- Basic WAF input filtering
- API endpoints
- Audit logging
- Administrator SIEM dashboard
- Simple HTML/CSS interface
- No classes required

## Repository structure

```text
secure_question_paper_management/
│
├── app.py
├── requirements.txt
├── README.md
├── .gitignore
│
├── templates/
│   ├── login.html
│   ├── mfa.html
│   ├── dashboard.html
│   └── siem.html
│
├── static/
│   └── style.css
│
└── data/
    └── (created automatically when the app runs)
        ├── kms.key
        ├── shard_1.json
        ├── shard_2.json
        └── immutable_ledger.log
```

## Run on Windows

Open Command Prompt/PowerShell inside the project folder:

```bash
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
python app.py
```

Open:

```text
http://127.0.0.1:5000
```

## Demo login

Question Setter:

```text
Username: setter
Password: setter123
```

Administrator:

```text
Username: admin
Password: admin123
```

After login, Flask prints the MFA OTP in the terminal:

```text
[DEMO MFA] OTP for setter: 123456
```

Enter that OTP in the browser.

## GitHub

Create a GitHub repository, then run:

```bash
git init
git add .
git commit -m "Initial secure question paper management system"
git branch -M main
git remote add origin https://github.com/YOUR_USERNAME/YOUR_REPOSITORY.git
git push -u origin main
```

Do not commit `data/kms.key`, user data, or real credentials.

## Notes for your project presentation

You can explain the flow as:

```text
User
  ↓
MFA / Role Login
  ↓
WAF
  ↓
API Gateway
  ↓
Encryption Engine + Sharding
  ↓
KMS
  ↓
Encrypted Shard 1 / Encrypted Shard 2
  ↓
Immutable Audit Log
  ↓
SIEM Dashboard
```

For a real deployment, replace the demo components with a managed identity provider, real WAF/API gateway, cloud KMS, managed database/storage, centralized immutable logging, HTTPS, secure secrets management, rate limiting, CSRF protection, and proper password hashing.
