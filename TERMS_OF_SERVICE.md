# Terms of Service

**Effective Date:** November 25, 2026  
**Last Updated:** November 25, 2026

Please read these Terms of Service ("Terms") carefully before using the SecureVault application, platform, or services ("Service", "Application", or "System").

---

## 1. Acceptance of Terms

By accessing, registering for, or using SecureVault, you acknowledge that you have read, understood, and agree to be bound by these Terms, as well as our [Security Policy](SECURITY.md) and [Privacy Policy](PRIVACY_POLICY.md). If you do not agree to these terms, you must discontinue use of the Service immediately.

---

## 2. User Responsibilities & Account Security

- **Master Password Confidentiality:** You are solely responsible for maintaining the secrecy of your master password and multi-factor authentication (MFA) devices. SecureVault does not store your master password in plaintext and cannot recover lost master passwords.
- **Accurate Contact Information:** You agree to maintain a valid, accessible email address associated with your account to receive critical step-up authentication challenges and security event alerts.
- **Account Loss Notice:** In the event that you lose access to both your master password and your configured multi-factor authentication mechanisms, you acknowledge that your encrypted vault content cannot be restored.

---

## 3. Data Protection & Sharing Safeguards

- **Server-Side Authenticated Encryption:** SecureVault encrypts your credentials using server-side AES-256-GCM. Decryption occurs strictly within authenticated user sessions authorized by signed JSON Web Tokens (JWT).
- **External Sharing Rules:** When using external credential sharing features, you are responsible for:
  - Verifying the identity of designated external recipients.
  - Selecting appropriate time expiration windows and one-time retrieval flags.
  - Promptly exercising revocation when access is no longer required.
- **Administrative Telemetry:** Authorized system administrators have access to platform operational telemetry and audit logs (such as login timestamps, client IP addresses, and failure counters). Administrative dashboards never expose decrypted user passwords or credential contents.

---

## 4. Acceptable Use Policy

You agree **NOT** to use SecureVault to:
1. Store or distribute unlawful, fraudulent, defamatory, or malicious content.
2. Interfere with, disrupt, or launch denial-of-service (DoS) attacks against the platform infrastructure.
3. Circumvent rate limiters, authentication barriers, or security controls.
4. Attempt unauthorized access to accounts, vaults, or data belonging to other users.
5. Probe, scan, or conduct automated penetration tests against the production infrastructure without prior written authorization from the system administrator.

---

## 5. Disclaimer of Warranties

The Service is provided on an **"AS IS"** and **"AS AVAILABLE"** basis, without warranties of any kind, whether express, statutory, or implied, including but not limited to implied warranties of merchantability, fitness for a particular purpose, or uninterrupted availability.

---

## 6. Limitation of Liability

To the fullest extent permitted by applicable law, in no event shall the operators, contributors, developers, or affiliates of SecureVault be liable for any direct, indirect, incidental, special, consequential, or punitive damages, including loss of data, unauthorized access, or business disruption resulting from your use of or inability to use the Service.

---

## 7. Modifications to Terms

We reserve the right to revise or update these Terms at any time. Material changes will be indicated by updating the revision date atop this document or via system notification within the application. Continued use of the Service following revisions constitutes acceptance of the modified Terms.

---

## 8. Inquiries & Contact

For questions regarding these Terms of Service, contact:  
**Support & Inquiries:** `rabishankarroy04@gmail.com` (or your designated SecureVault System Administrator).
