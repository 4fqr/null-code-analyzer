"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
Command injection vulnerabilities
"""

import os
import subprocess


def vulnerable_ping_v1(host):
    """Command injection via os.system"""
    # VULNERABLE: User input directly in system command
    os.system(f"ping -c 4 {host}")


def vulnerable_ping_v2(target):
    """Command injection via subprocess.call"""
    # VULNERABLE: Shell=True with user input
    subprocess.call(f"nmap -sV {target}", shell=True)


def vulnerable_backup(filename):
    """Command injection via string concatenation"""
    # VULNERABLE: String concatenation in command
    command = "tar -czf backup.tar.gz " + filename
    subprocess.run(command, shell=True)


def vulnerable_eval(user_code):
    """Code injection via eval"""
    # VULNERABLE: eval with user input
    result = eval(user_code)
    return result


def vulnerable_exec(user_script):
    """Code injection via exec"""
    # VULNERABLE: exec with user input
    exec(user_script)


# SAFE EXAMPLE
def safe_ping(host):
    """Safe command execution - parameterized"""
    # SAFE: List arguments, no shell
    subprocess.run(["ping", "-c", "4", host], shell=False)
