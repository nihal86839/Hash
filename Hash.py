Sourcery
Weak Password Hashing Algorithms and Practices
High Risk
Cryptographic Security
password-hashing
authentication
bcrypt
scrypt
argon2
pbkdf2
salting
rainbow-tables
brute-force
password-storage
What it is
A critical vulnerability where applications use weak password hashing algorithms (MD5, SHA-1, SHA-256 without salt) or implement password hashing incorrectly. This makes stored passwords vulnerable to rainbow table attacks, brute force attacks, and password recovery through cryptographic weaknesses.

Language:
Python
❌ Vulnerable
✅ Secure
# Python - VULNERABLE: Multiple weak password practices
import hashlib
import sqlite3
import time
from datetime import datetime

class VulnerableAuthSystem:
    def __init__(self, db_path="users.db"):
        self.conn = sqlite3.connect(db_path)
        self.create_tables()
    
    def create_tables(self):
        cursor = self.conn.cursor()
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS users (
                id INTEGER PRIMARY KEY,
                username TEXT UNIQUE,
                password_hash TEXT,
                created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            )
        """)
        self.conn.commit()
    
    def hash_password_md5(self, password):
        """VULNERABLE: Using MD5 for password hashing"""
        return hashlib.md5(password.encode()).hexdigest()
    
    def hash_password_sha256_no_salt(self, password):
        """VULNERABLE: SHA-256 without salt"""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def hash_password_weak_salt(self, password, username):
        """VULNERABLE: Predictable salt based on username"""
        salt = username.lower()  # Predictable salt!
        salted_password = password + salt
        return hashlib.sha256(salted_password.encode()).hexdigest()
    
    def register_user(self, username, password):
        """VULNERABLE: No password policy enforcement"""
        cursor = self.conn.cursor()
        
        # No password strength validation
        if len(password) < 3:  # Extremely weak requirement
            return False, "Password too short"
        
        # Using weak hashing method
        password_hash = self.hash_password_weak_salt(password, username)
        
        try:
            cursor.execute(
                "INSERT INTO users (username, password_hash) VALUES (?, ?)",
                (username, password_hash)
            )
            self.conn.commit()
            return True, "User registered successfully"
        except sqlite3.IntegrityError:
            return False, "Username already exists"
    
    def login_user(self, username, password):
        """VULNERABLE: Multiple authentication issues"""
        cursor = self.conn.cursor()
        
        cursor.execute(
            "SELECT password_hash FROM users WHERE username = ?",
            (username,)
        )
        
        result = cursor.fetchone()
        if not result:
            return False, "User not found"
        
        stored_hash = result[0]
        
        # VULNERABLE: Try multiple hash methods (revealing hash type)
        computed_hash_md5 = self.hash_password_md5(password)
        computed_hash_sha256 = self.hash_password_sha256_no_salt(password)
        computed_hash_weak_salt = self.hash_password_weak_salt(password, username)
        
        # VULNERABLE: Timing attack possible
        if (stored_hash == computed_hash_md5 or 
            stored_hash == computed_hash_sha256 or 
            stored_hash == computed_hash_weak_salt):
            return True, "Login successful"
        
        return False, "Invalid password"
    
    def change_password(self, username, old_password, new_password):
        """VULNERABLE: No verification of old password strength"""
        # Verify old password first
        login_success, _ = self.login_user(username, old_password)
        if not login_success:
            return False, "Current password incorrect"
        
        # No validation of new password strength
        if len(new_password) < 3:
            return False, "New password too short"
        
        # Update with same weak hashing
        new_hash = self.hash_password_weak_salt(new_password, username)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (new_hash, username)
        )
        self.conn.commit()
        
        return True, "Password changed successfully"
    
    def reset_password(self, username):
        """VULNERABLE: Weak password reset"""
        # Generate weak temporary password
        import random
        temp_password = str(random.randint(100000, 999999))  # 6-digit number
        
        # Hash with weak method
        temp_hash = self.hash_password_weak_salt(temp_password, username)
        
        cursor = self.conn.cursor()
        cursor.execute(
            "UPDATE users SET password_hash = ? WHERE username = ?",
            (temp_hash, username)
        )
        self.conn.commit()
        
        return temp_password  # DANGEROUS: Returning plaintext password
    
    def get_user_passwords(self):
        """VULNERABLE: Exposing password hashes"""
        cursor = self.conn.cursor()
        cursor.execute("SELECT username, password_hash FROM users")
        return cursor.fetchall()
    
    def bulk_password_check(self, password_list):
        """VULNERABLE: Allows bulk password testing"""
        results = []
        
        for password in password_list:
            for username, stored_hash in self.get_user_passwords():
                computed_hash = self.hash_password_weak_salt(password, username)
                if computed_hash == stored_hash:
                    results.append((username, password))
        
        return results
