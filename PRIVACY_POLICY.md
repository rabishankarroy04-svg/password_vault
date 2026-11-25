# Privacy Policy

**Effective Date:** November 25, 2026  
**Last Updated:** November 25, 2026

SecureVault ("we", "us", or "our") is committed to protecting your privacy and ensuring the confidentiality, integrity, and security of your stored credentials. This Privacy Policy details the types of information we collect, how it is processed and protected, and your rights concerning your personal data.

---

## 1. Information We Collect

### 1.1 Account Information
- **Registration Data:** Username, email address, salted password hash (BCrypt), and account creation timestamps.
- **Multi-Factor Authentication (MFA):** Encrypted TOTP authenticator seeds and temporary verification challenge state.

### 1.2 Vault Content & Metadata
- **Stored Credentials:** Account titles, usernames, target URLs, passwords, and custom notes. All credential values are encrypted server-side with **AES-256-GCM** using keys derived uniquely per user before persistence.
- **Categorization & Preferences:** User-defined category tags and favorite flags.
- **Vault Metadata:** Last modified timestamps and item counters.

### 1.3 Technical Telemetry & Audit Logs
- **Device Identifiers:** Cryptographically pseudo-random device identifiers (`securevault_device_fingerprint_v1`) stored in client-side storage to identify recognized devices.
- **Network Telemetry:** Public client IP addresses (derived securely via validated reverse-proxy `X-Forwarded-For` headers), browser User-Agent strings, and session timestamps.
- **Audit Logging:** Immutably recorded system events, including sign-in attempts, MFA verifications, credential creations/updates/deletions, and external share access events.

---

## 2. How We Use Collected Information

Information collected by SecureVault is utilized strictly to:
- Authenticate and maintain active user sessions.
- Securely encrypt, store, decrypt, and manage your private credentials.
- Detect, alert on, and mitigate unauthorized access attempts, brute-force attacks, and credential stuffing.
- Deliver critical security verification challenges (MFA codes) and external credential sharing links.
- Provide administrative auditability and regulatory compliance reporting to authorized system administrators.

---

## 3. Third-Party Integrations & External Services

### 3.1 Have I Been Pwned (HIBP) Password Health Checks
When you initiate a password health or breach assessment, SecureVault implements strict **$k$-Anonymity**:
- The password is hashed using SHA-1.
- **Only the first 5 hexadecimal characters** of the hash prefix are transmitted to the external HIBP API (`api.pwnedpasswords.com`).
- The remaining 35 characters and your plaintext password **never leave the secure application server**.
- The server matches returned hash suffixes locally in memory.

### 3.2 Outbound Transactional Email Routing
Transactional verification emails (MFA sign-in codes and external credential share invitations) are dispatched through external email delivery services:
- **Brevo REST API / Resend REST API:** Dispatched via encrypted HTTPS (TLS port 443) to prevent unencrypted SMTP interception or cloud ISP port blocks.
- **Data Transmitted:** Outbound email payloads contain only transient 6-digit numeric verification codes or single-use share invitation tokens. **Plaintext master passwords and vault secrets are never included in email transmissions.**

---

## 4. Data Protection & Cryptographic Safeguards

- **Server-Side Authenticated Encryption (SSE):** Credential fields are encrypted with AES-256-GCM with 96-bit nonces and AAD binding (`SecureVault/credential/v1/owner/id`). Sub-keys are derived via HMAC-SHA256 from a root secret.
- **Token Fingerprinting:** Raw JSON Web Tokens (JWT) are never stored in the database. Only one-way SHA-256 hashes of tokens are recorded for session invalidation tracking.
- **Memory Protection:** Plaintext secrets are cleared from memory as soon as cryptographic transformations conclude.

---

## 5. Data Retention & Deletion

- **Soft & Hard Deletion:** Deleted credentials are immediately marked as soft-deleted and removed from active vault queries. Any active external shares linked to the credential are instantaneously revoked.
- **Session Lifetimes:** Inactive user session tokens expire automatically after 15 minutes (or the configured JWT lifetime).
- **Audit Records:** Audit log entries are retained permanently or according to organizational compliance schedules to support forensic investigations and threat analysis.

---

## 6. Contact Information

For inquiries regarding this Privacy Policy or data security practices, contact:  
**Security & Privacy Contact:** `rabishankarroy04@gmail.com` (or your designated SecureVault System Administrator).
