"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
Path traversal vulnerabilities
"""

import os


def vulnerable_read_file_v1(filename):
    """Path traversal via user input"""
    # VULNERABLE: User can supply ../../../etc/passwd
    with open(filename, 'r') as f:
        return f.read()


def vulnerable_read_file_v2(user_file):
    """Path traversal via path concatenation"""
    # VULNERABLE: Direct concatenation
    base_path = "/var/www/uploads/"
    file_path = base_path + user_file
    
    with open(file_path, 'r') as f:
        return f.read()


def vulnerable_read_file_v3(doc_name):
    """Path traversal via os.path.join with user input"""
    # VULNERABLE: os.path.join with unsanitized input
    docs_dir = "/home/user/documents"
    full_path = os.path.join(docs_dir, doc_name)
    
    return open(full_path).read()


# SAFE EXAMPLE
def safe_read_file(filename):
    """Safe file reading with path validation"""
    import os.path
    
    # SAFE: Validate input
    base_path = "/var/www/uploads/"
    
    # Resolve absolute path and check it's within base_path
    full_path = os.path.abspath(os.path.join(base_path, filename))
    
    if not full_path.startswith(os.path.abspath(base_path)):
        raise ValueError("Invalid file path")
    
    with open(full_path, 'r') as f:
        return f.read()
