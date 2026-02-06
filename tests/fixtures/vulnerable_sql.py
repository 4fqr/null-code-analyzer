"""
INTENTIONALLY VULNERABLE CODE - FOR TESTING ONLY
This file contains SQL injection vulnerabilities for scanner validation
"""

import sqlite3
import MySQLdb


def vulnerable_login_v1(username, password):
    """SQL Injection via string concatenation"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Direct string concatenation
    query = "SELECT * FROM users WHERE username = '" + username + "' AND password = '" + password + "'"
    cursor.execute(query)
    
    return cursor.fetchone()


def vulnerable_login_v2(user_id):
    """SQL Injection via format string"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # VULNERABLE: Using format string
    query = "SELECT * FROM users WHERE id = {}".format(user_id)
    cursor.execute(query)
    
    return cursor.fetchone()


def vulnerable_search(search_term):
    """SQL Injection via f-string"""
    conn = MySQLdb.connect(host="localhost", user="root")
    cursor = conn.cursor()
    
    # VULNERABLE: f-string interpolation
    query = f"SELECT * FROM products WHERE name LIKE '%{search_term}%'"
    cursor.execute(query)
    
    return cursor.fetchall()


# SAFE EXAMPLE (for comparison)
def safe_login(username, password):
    """Parameterized query - SAFE"""
    conn = sqlite3.connect('users.db')
    cursor = conn.cursor()
    
    # SAFE: Using parameterized query
    query = "SELECT * FROM users WHERE username = ? AND password = ?"
    cursor.execute(query, (username, password))
    
    return cursor.fetchone()
