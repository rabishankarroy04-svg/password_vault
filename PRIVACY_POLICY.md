# Privacy Policy

**Effective Date:** November 23, 2026  
**Last Updated:** November 23, 2026

SecureVault ("we", "us", or "our") is dedicated to safeguarding your privacy and protecting the security of your stored credentials. This Privacy Policy details what information we collect, how it is secured, and your rights.

---

## 1. Information We Collect

### 1.1 Account Information
- **Registration Data:** Username, email address, password hash (salted BCrypt), and enrollment timestamps.
- **Multi-Factor Authentication (MFA):** Encrypted TOTP authenticator seeds and temporary challenge state.

### 1.2 Vault Content
- **Stored Credentials:** Account titles, usernames, URLs, passwords, and custom notes. All vault credential content is encrypted with AES-256-GCM before persistent database storage.
- **Categories & Favorites:** Folder organization and favorite flags.

### 1.3 Technical & Telemetry Data
- **Device Fingerprints:** Randomly generated device identifiers (`securevault_device_fingerprint_v1`) stored in client-side storage to recognize trusted devices.
- **Session Data:** Client IP addresses, browser User-Agent strings, login timestamps, and session token SHA-256 fingerprints.
- **Audit Logs:** Security events including registration, login success/failure, MFA verification, credential read/write operations, and access denials.

---

## 2. How We Use Information

We process collected information exclusively to:
- Authenticate and manage your session.
- Securely store, retrieve, and organize your credential vault.
- Detect, alert on, and mitigate suspicious account activity (e.g. brute-force attacks, logins from anomalous IP locations).
- Dispatch critical verification emails, external credential shares, and account security notifications via SMTP.

---

## 3. Third-Party Integrations & External Services

- **HIBP K-Anonymity Breach Checking:** When you use the password health breach check feature, SecureVault hashes the candidate password using SHA-1 and sends **only the first 5 hexadecimal characters** of the hash to the Have I Been Pwned API (`api.pwnedpasswords.com`). The remainder of the hash and your plaintext password never leave the server.
- **Email Delivery (SMTP):** Verification codes and external share invitations are routed through your configured SMTP provider (e.g. Mailpit for local testing, or Google Gmail SMTP for production).

---

## 4. Data Retention & Deletion

- **Soft & Hard Deletion:** When a credential is deleted, it is flagged with a deletion timestamp and excluded from active vault queries. Associated active shares are immediately revoked.
- **Session Expiration:** Inactive authentication tokens expire automatically after 15 minutes (or the configured JWT lifetime).
- **Audit Trail:** Security audit entries are retained for compliance, forensic investigation, and threat monitoring.

---

## 5. Contact Information

For inquiries regarding this Privacy Policy or your personal data, contact:  
**Email:** `privacy@example.com` (or your SecureVault system administrator).
