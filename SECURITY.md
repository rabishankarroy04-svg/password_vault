# SecureVault Security Policy

**Effective Date:** November 23, 2026  
**Document Version:** 1.0  
**Scope:** SecureVault Unified Application (Spring Boot Backend, React Frontend, PostgreSQL Database)

---

## 1. Security Architecture & Threat Model

SecureVault provides an encrypted credential management platform designed with multi-layered defense-in-depth principles:

### 1.1 Cryptographic Architecture
- **Vault Credential Encryption:** Credentials (username, password, URL, notes) are encrypted server-side using **AES-256-GCM (Galois/Counter Mode)** with 96-bit unique cryptographic nonces.
- **Key Isolation & Derivation:** Vault encryption keys are never stored directly in the database. A root secret (`VAULT_ENCRYPTION_KEY_BASE64`) derives individual, tenant-isolated sub-keys for each user using `HMAC-SHA256("SecureVault/credential/v1/" + owner_uuid)`.
- **Ciphertext Integrity & AAD Binding:** Every encrypted credential employs Additional Authenticated Data (AAD) binding `("SecureVault/credential/v1/" + owner + "/" + credential)`. This cryptographically prevents ciphertext transplantation across accounts or records.
- **Password Hashing:** User passwords are encrypted using **BCrypt** with unique cryptographic salts, enforcing a strict 72-byte ceiling to prevent truncation bypasses.
- **MFA Seed Encryption:** TOTP seeds are encrypted at rest with AES-256-GCM using keys derived from a distinct `MFA_ENCRYPTION_KEY_BASE64`.

### 1.2 Authentication & Session Management
- **Stateless Bearer Tokens:** Authenticated sessions use signed JSON Web Tokens (JWT) signed via HMAC-SHA384/512 with a minimum 48-byte random key requirement.
- **Token Fingerprinting:** Raw JWTs are never stored in the database. Database sessions only store SHA-256 digests (`SessionTokenUtils.fingerprint()`).
- **Session Revocation:** Logout explicitly marks the active database session revoked (`is_revoked = TRUE`).
- **Timing-Attack Resistance:** Unregistered user lookups trigger synthetic BCrypt hash computations (`dummyHash`) to eliminate user-enumeration side-channel timing discrepancies.

### 1.3 Threat Detection & Brute-Force Defense
- **Per-IP Rate Limiting:** Global rate-limiting filter (`AuthRateLimitFilter`) strictly limits `/api/login` (30 req/min) and `/api/registration` (15 req/min).
- **Concurrency & DoS Safeguards:** Semaphores cap concurrent authentication requests to 16 in-flight connections to defend against slowloris exhaustion. Request bodies are limited to 8 KiB.
- **Account Lockout:** 5 consecutive failed login attempts trigger an automatic 15-minute account lockout.
- **Risk-Based Step-Up Verification:** Logins from new IP addresses or unregistered devices without TOTP MFA require mandatory 6-digit email OTP challenges.

### 1.4 Least Privilege & Database Security
- The application executes using a restricted PostgreSQL role (`securevault_app`) with minimal table-level permissions.
- Audit logs and security event logs are structurally write-protected against retroactive tampering.
- All database interactions use parameterized SQL statements via `JdbcTemplate` to eliminate SQL injection vulnerabilities.

---

## 2. Server-Side Encryption Disclosure

> [!IMPORTANT]
> **Trust Boundary Notice:** SecureVault implements **Server-Side Authenticated Encryption (SSE)**.
> While data is encrypted at rest in PostgreSQL and encrypted in transit via TLS, the encryption keys are managed by the server environment. Server operators and administrators with access to the runtime memory and root environment keys possess the technical capability to decrypt stored secrets.
> Organizations requiring zero-knowledge/client-side end-to-end encryption must implement browser-side key derivation prior to submission.

---

## 3. Vulnerability Reporting & Responsible Disclosure

We welcome responsible security research and vulnerability reporting.

If you identify a security vulnerability within SecureVault, please follow these guidelines:

1. **Do NOT open a public GitHub issue.**
2. Send a detailed report to the security contact: **security@example.com** (or contact the repository administrator directly).
3. Provide actionable reproduction steps, impact assessment, and proof of concept where applicable.
4. Allow reasonable time (typically 30–90 days) for review, patching, and verification prior to public disclosure.

---

## 4. Security Best Practices for Operators

1. **Enforce HTTPS:** SecureVault must always be deployed behind an SSL/TLS reverse proxy (Caddy, NGINX, Cloudflare) with HSTS enabled.
2. **Key Rotation & Protection:** Store `.env` configuration securely outside web roots. Do not check `.env` into source control.
3. **SMTP Security:** Ensure outbound email uses STARTTLS with verified certificate chains (`SPRING_MAIL_PROPERTIES_MAIL_SMTP_SSL_CHECKSERVERIDENTITY=true`).
