# DIWA Stage 2 Verification Report

**Scope:** DIWA repository at local commit `5dde6211ab65a2f089388c2cd454d5187a2061ec`.
**Run target:** `http://127.0.0.1:8080`.
**Run date:** 2026-09-21.

## Execution status

The local target was not running: connection to `127.0.0.1:8080` failed. The Python scripts also could not start because the environment does not have the `requests` package installed. Therefore no dynamic finding is marked confirmed by runtime testing. Classifications below distinguish **code-supported**, **not reproducible/likely false positive**, and **blocked**.

## Final finding list

| Scan ID | Finding | Result | Evidence / reason |
|---|---|---|---|
| SCAN-002 | SQL injection in login | **Code-supported; dynamic test blocked** | DIWA `userSignIn()` concatenates email into SQL. Run `01_sqli_login.py` against a running local instance to confirm behavior. |
| SCAN-004 | Path traversal in `download.php` | **Code-supported; dynamic test blocked** | `readfile()` receives a path built from `$_GET['file']` without a directory-boundary check. |
| SCAN-001 | LFI in page routing | **Likely false positive / not reproducible from cited payload** | `index.php` appends `.php` to the selected page; `../../../../etc/passwd` becomes a non-existent `passwd.php`. This may still warrant allowlist hardening, but the supplied `/etc/passwd` proof does not demonstrate LFI. |
| SCAN-008 | Stored XSS in forum posts | **Code-supported; dynamic test blocked** | Post content is insufficiently filtered and rendered without reliable output encoding. Run `04_xss_stored_post.py`. |
| SCAN-005 | IDOR in profile editing | **Code-supported; dynamic test blocked** | `editprofile.php` accepts an arbitrary `id` and uses it as the target without an ownership/admin authorization check. The supplied test requires two user accounts. |
| SCAN-006 | Reflected XSS in messages notification | **Code-supported; dynamic test blocked** | The reported `messagesent.php` behavior directly echoes `message`; the endpoint should be verified with a harmless inert marker. |
| SCAN-007 | Missing permission check in download management | **Code-supported; dynamic test blocked** | Administrative actions are processed before the authorization check in the cited file. Use a non-admin session and a disposable record only. |
| SCAN-010 | Missing CSRF protection | **Code-supported; dynamic test blocked** | State-changing forms lack a token and server-side validation. A same-site local browser test is required for behavioral confirmation. |
| SCAN-009 | MD5 password hashing | **Confirmed by source/configuration** | The reported configuration uses MD5. This is a cryptographic weakness rather than a request-triggered vulnerability. Replace with `password_hash()`/`password_verify()`. |
| CK-Q1-F091 | Hardcoded AWS key in `config/settings.py` | **False positive / not applicable to this repository** | No cited Python file is present in DIWA. The finding belongs to a different repository or scan snapshot. |
| CK-Q1-F372 | SQL injection in legacy order lookup | **False positive / not applicable** | `api/orders/views_legacy.py` is not part of DIWA; the reported 401 response does not demonstrate SQL execution. |
| CK-Q1-F354 | Stack traces returned to clients | **False positive / not applicable** | `api/middleware.py` is not part of DIWA, and the supplied response contains only `internal_error`, not a stack trace. |
| SCAN-011 | SQL injection in profile updates | **Code-supported; dynamic test blocked** | The reported update concatenates user-controlled profile fields into SQL. Verify only with a harmless quote marker, not a modifying SQL payload. |
| CK-Q1-F331 | SQL injection in internal report filter | **False positive / not applicable** | `analytics/report_sql_internal.py` is not part of DIWA; the supplied 400 response shows rejection, not injection. |
| CK-Q1-F069 | SQL injection in v2 order lookup | **False positive / not applicable** | `api/orders/views_v2.py` is not part of DIWA; the supplied 401 response does not confirm injection. |
| CK-Q1-F036 | Mass assignment of role | **False positive / not applicable** | `api/users_update.py` is not part of DIWA, and the response retained `PARTICIPANT`, showing the role was not changed. |
| CK-Q1-F178 | Missing CSRF on health check | **False positive / not applicable** | `ops/health_v2.py` is not part of DIWA. A read-only GET health check normally does not require CSRF protection. |

## Scripts available

The repository contains the prior local-only scripts in `stage2_poc_scripts/`. They cover the DIWA findings that can be exercised over HTTP. They should be run only after starting the Docker container from the README and installing `requests` in the test environment.

## Remediation priorities

1. Replace every SQL string concatenation involving request data with PDO prepared statements.
2. Enforce authorization server-side for profile, post, and download-management actions; derive the target user from the session unless an explicit admin permission is present.
3. Encode output with `htmlspecialchars($value, ENT_QUOTES, 'UTF-8')`; do not rely on regex filtering for XSS.
4. Restrict page/file selection to allowlists and enforce `realpath()` containment beneath the intended directory.
5. Validate uploads by allowlisted type, randomize names, store outside the executable web root, and disable script execution there.
6. Add session-bound CSRF tokens to every state-changing request and validate them server-side.
7. Replace MD5 with `password_hash()` and `password_verify()`, then rotate any exposed secrets.

**Important:** “Code-supported” is not the same as “runtime confirmed.” A final security sign-off should rerun the scripts against a clean local container and record HTTP status, response marker, and test timestamp for each ID.

## Reproduction command

```text
docker build -t diwa . && docker run -p 8080:80 -d diwa:latest
cd stage2_poc_scripts
python3 01_sqli_login.py
# repeat for the remaining scripts
```

Do not run the scripts against public, third-party, or production hosts.
