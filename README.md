# Secure Cloud-Based Question Paper Management System

Simple Flask implementation of the five-tier architecture supplied in the project diagram.

## Why this version works on Vercel

The application does **not** try to create files such as `data/kms.key` inside the deployed project. Serverless deployments should not depend on writing persistent application data to the project directory.

For this academic demo, encrypted questions, shards and audit logs are held in memory.

For a production system, replace those parts with:
- Cloud KMS
- PostgreSQL/Supabase or another managed database
- Object storage
- Real WAF
- Real API gateway
- Centralized immutable logging/SIEM

## Structure

```text
secure_question_paper_management/
│
├── vercel.json
├── requirements.txt
├── README.md
├── .gitignore
│
└── app/
    ├── __init__.py
    ├── main.py
    │
    ├── templates/
    │   ├── login.html
    │   ├── mfa.html
    │   ├── dashboard.html
    │   └── siem.html
    │
    └── static/
        └── style.css
```

## Local run

```bash
python -m venv venv
```

Windows:

```bash
venv\Scripts\activate
```

Linux/macOS:

```bash
source venv/bin/activate
```

Install:

```bash
pip install -r requirements.txt
```

Run:

```bash
python app/main.py
```

Open:

```text
http://127.0.0.1:5000
```

## Demo accounts

```text
setter / setter123
admin / admin123
```

## Vercel deployment

Push this entire folder to GitHub and import the repository into Vercel.

The included `vercel.json` tells Vercel to use:

```text
app/main.py
```

as the Python serverless entry point.

### Optional Vercel environment variables

Set these in Vercel:

```text
SECRET_KEY=your-random-secret
ENCRYPTION_KEY=your-fernet-key
```

To generate an encryption key locally:

```bash
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
```

Do not commit real secrets to GitHub.

## Architecture mapping

Tier 1:
- Login
- Role-based access
- MFA demo

Tier 2:
- WAF input filtering
- API Gateway-style `/api/*` routes

Tier 3:
- Dynamic encryption
- Subject-based sharding

Tier 4:
- KMS simulation
- Encrypted data shards

Tier 5:
- Audit events
- SIEM dashboard

## Important academic-project limitation

This project is intentionally simple. The MFA, WAF, API gateway, KMS and SIEM components are educational simulations, not production-grade security infrastructure.
