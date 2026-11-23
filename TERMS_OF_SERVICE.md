# Terms of Service

**Effective Date:** November 23, 2026  
**Last Updated:** November 23, 2026

Please read these Terms of Service ("Terms") carefully before using the SecureVault application ("Service", "Application", or "System").

---

## 1. Acceptance of Terms

By accessing, registering an account with, or utilizing SecureVault, you agree to be bound by these Terms and our [Security Policy](SECURITY.md) and [Privacy Policy](PRIVACY_POLICY.md). If you do not agree, you must immediately cease use of the Service.

---

## 2. Account Security & Responsibilities

- **Master Password:** You are solely responsible for maintaining the confidentiality of your master password and multi-factor authentication credentials. SecureVault does not retain master passwords in plaintext.
- **Account Recovery:** You acknowledge that lost passwords or lost TOTP authenticator devices without alternative verification channels may result in permanent loss of access to stored vault credentials.
- **Accurate Information:** You agree to provide a valid, accessible email address during registration to receive risk-based login challenges, security incident notifications, and external share invitations.

---

## 3. Data Protection & Encryption Model

- **Server-Side Encryption:** Credentials stored within SecureVault are protected using server-side authenticated encryption (AES-256-GCM). Data is encrypted before storage in the database and decrypted on-demand when requested by authenticated sessions.
- **External Sharing:** When you generate an external credential share, an encrypted link and verification code are generated for the designated recipient. You are solely responsible for verifying the identity of external recipients and setting appropriate expiration limits.

---

## 4. Acceptable Use Policy

You agree **NOT** to use SecureVault to:
1. Store or transmit unlawful, malicious, or infringing materials.
2. Attempt unauthorized access to other users' vaults, system services, or infrastructure.
3. Circumvent rate limits, authentication controls, or administrative security policies.
4. Conduct automated denial-of-service (DoS) or load-testing attacks against the application.
5. Probe, scan, or exploit security vulnerabilities without prior written authorization from the system administrator.

---

## 5. Administrative Oversight

- System administrators have access to platform telemetry, audit logs, and account metadata (including user counts, device registrations, and failed login frequencies).
- In accordance with our security principles, administrative APIs **never** expose decrypted passwords or vault contents to administrative dashboards.

---

## 6. Disclaimer of Warranties

The Service is provided **"AS IS"** and **"AS AVAILABLE"**, without warranties of any kind, whether express, statutory, or implied, including but not limited to implied warranties of merchantability, fitness for a particular purpose, or uninterrupted availability.

---

## 7. Limitation of Liability

To the maximum extent permitted by applicable law, in no event shall the operators, contributors, or authors of SecureVault be liable for any indirect, incidental, special, consequential, or punitive damages, including loss of data, unauthorized access, or loss of profits arising out of or related to your use of the Service.

---

## 8. Modifications to Terms

We reserve the right to revise or update these Terms at any time. Notice of significant revisions will be provided through system notifications or by updating the revision date atop this document.
