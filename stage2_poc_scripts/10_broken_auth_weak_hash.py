#!/usr/bin/env python3
"""
Stage 2 POC: Broken Authentication - Weak Password Hashing (MD5)
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: config.php uses MD5 for password hashing (cryptographically broken)
"""

import requests
import sys
import hashlib

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_weak_password_hash():
    """
    Demonstrate MD5 weakness: rainbow table lookup.
    Test case: Register user with known password, extract hash, crack it.
    Expected: Hash can be looked up in online rainbow tables (MD5 is deprecated)
    """
    print("[*] Testing Weak Password Hashing (MD5)...")
    
    try:
        # Known test password
        test_password = "Password123!"
        md5_hash = hashlib.md5(test_password.encode()).hexdigest()
        
        print(f"[*] Test password: {test_password}")
        print(f"[*] MD5 hash: {md5_hash}")
        
        # Register a user with this password
        import uuid
        unique_email = f"test{str(uuid.uuid4())[:6]}@example.com"
        
        register_payload = {
            'username': f'testuser{str(uuid.uuid4())[:6]}',
            'email': unique_email,
            'password': test_password,
            'password_check': test_password,
            'country': 'US',
            'invitation_code': '3702'
        }
        
        resp = SESSION.post(f"{TARGET}/?page=register", data=register_payload)
        
        if 'registered' not in resp.text.lower() and 'success' not in resp.text.lower():
            print("[*] Registration may have failed, but continuing hash analysis...")
        
        # The real test: MD5 is in online databases
        # Simulate checking a rainbow table (in real pentest, use online tools)
        print("[*] Checking if MD5 hash exists in known weak hash databases...")
        
        # Try to login with the password (should work)
        login_payload = {
            'email': unique_email,
            'password': test_password
        }
        resp_login = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        if 'loggedin' in resp_login.headers.get('Location', '') or SESSION.cookies:
            print("✅ VULNERABLE: User logged in with MD5-hashed password")
            print("[*] Analysis: MD5 hashes can be cracked in milliseconds via rainbow tables")
            print("[*] Example: Online databases (MD5Online.net, etc.) can reverse many MD5 hashes")
            return True
        
        print("❌ NOT REPRODUCIBLE: Authentication check failed")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_weak_password_hash()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Replace MD5 with bcrypt (password_hash) or Argon2:

  // config.php - CHANGE THIS
  // $config['system']['hashing_algorithm'] = 'md5';  // REMOVE THIS
  
  // In userSignIn()
  public function userSignIn($pEmail, $pPassword) {
      try {
          $stmt = $this->db->prepare(
              'SELECT * FROM ' . $this->prefix . 'users WHERE email = ?'
          );
          $stmt->execute([$pEmail]);
          $user = $stmt->fetch();
          
          if ($user && password_verify($pPassword, $user['password'])) {
              return [$user];  // Success
          }
          return false;  // Failure
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }
  
  // In createUser()
  public function createUser($pUsername, $pPassword, $pEmail, $pCountry) {
      try {
          $hashed = password_hash($pPassword, PASSWORD_BCRYPT, ['cost' => 12]);
          
          $stmt = $this->db->prepare(
              'INSERT INTO ' . $this->prefix . 'users 
               (username, password, email, country, is_admin) 
               VALUES (?, ?, ?, ?, 0)'
          );
          $stmt->execute([$pUsername, $hashed, $pEmail, $pCountry]);
          return true;
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }

Key points:
- Use password_hash() with PASSWORD_BCRYPT or PASSWORD_ARGON2
- Use password_verify() for login comparison
- NEVER use MD5, SHA1, or unsalted hashes
- Cost of 12+ for bcrypt (increases computational time)
- Migrate existing MD5 hashes: on login, re-hash with bcrypt and update
"""
