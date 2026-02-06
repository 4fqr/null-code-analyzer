"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
Hardcoded secrets and credentials
"""

import requests


# VULNERABLE: Hardcoded API key
API_KEY = "sk_test_FAKE1234567890abcdefghijklmnop"

# VULNERABLE: Hardcoded database password
DB_PASSWORD = "MyS3cr3tPa$$w0rd123"

# VULNERABLE: AWS credentials
AWS_ACCESS_KEY = "AKIAIOSFODNN7EXAMPLE"
AWS_SECRET_KEY = "wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"


def authenticate_user():
    """Hardcoded credentials in code"""
    # VULNERABLE: Hardcoded admin password
    admin_password = "admin123456"
    
    if input("Password: ") == admin_password:
        return True
    return False


def connect_to_api():
    """Hardcoded API token"""
    # VULNERABLE: GitHub personal access token
    github_token = "ghp_1234567890abcdefghijklmnopqrstuvwxyz"
    
    headers = {"Authorization": f"Bearer {github_token}"}
    response = requests.get("https://api.github.com/user", headers=headers)
    return response.json()


class DatabaseConfig:
    """Hardcoded connection strings"""
    # VULNERABLE: Database credentials in class
    HOST = "db.example.com"
    USER = "admin"
    PASSWORD = "SuperSecret2024!"
    SECRET_KEY = "django-insecure-key-1234567890abcdefgh"


# SAFE EXAMPLE
def safe_connect():
    """Safe credential handling using environment variables"""
    import os
    
    # SAFE: Load from environment
    api_key = os.environ.get('API_KEY')
    db_password = os.environ.get('DB_PASSWORD')
    
    return api_key, db_password
