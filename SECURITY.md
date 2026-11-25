# SecureVault Security Policy

**Effective Date:** November 25, 2026  
**Document Version:** 1.1  
**Scope:** SecureVault Unified Application (Spring Boot Backend, React Frontend, PostgreSQL Database)

---

## 1. Security Architecture & Threat Model

SecureVault is built upon multi-layered defense-in-depth principles to protect sensitive credentials against unauthorized disclosure, tampering, side-channel attacks, and infrastructure compromise.

```
                           ┌─────────────────────────────────────────┐
                           │          Client Web Browser             │
                           └────────────────────┬────────────────────┘
                                                │ TLS 1.3 (HTTPS)
                                                ▼
                           ┌─────────────────────────────────────────┐
                           │   Cloud Reverse Proxy / Edge Router     │
                           └────────────────────┬────────────────────┘
                                                │ X-Forwarded-For + Sanitized IP
                                                ▼
       ┌──────────────────────────────────────────────────────────────────────────────────┐
       │                        Spring Boot Application Boundary                          │
       │                                                                                  │
       │  ┌────────────────────────┐  ┌───────────────────────┐  ┌─────────────────────┐  │
       │  │  AuthRateLimitFilter   │  │   ClientIpResolver    │  │ SecurityFilterChain │  │
       │  │ (30 req/min; 16 conc.) │  │ (Trusted Proxy CIDRs) │  │ (JWT Fingerprinting)│  │
       │  └───────────┬────────────┘  └───────────┬───────────┘  └──────────┬──────────┘  │
       │              └───────────────────────────┼─────────────────────────┘             │
       │                                          ▼                                       │
       │                        ┌───────────────────────────────────┐                     │
       │                        │   VaultEncryptionService (GCM)    │                     │
       │                        │  HMAC-SHA256 Sub-Key Derivation   │                     │
       │                        │  AAD Binding (Owner + Record ID)  │                     │
       │                        └─────────────────┬─────────────────┘                     │
       └──────────────────────────────────────────┼───────────────────────────────────────┘
                                                  ▼
                                ┌───────────────────────────────────┐
                                │       PostgreSQL 16 Storage       │
                                │   Restricted 'securevault' Role   │
                                │   Encrypted Ciphertext & Nonces   │
                                └───────────────────────────────────┘
```

---

## 2. Cryptographic Specifications

### 2.1 Vault Credential Encryption (AES-256-GCM)
- **Algorithm:** AES-256 in Galois/Counter Mode (GCM) with 128-bit authentication tag verification.
- **Cryptographic Nonce:** 96-bit unique pseudo-random initialization vector (IV) generated via `java.security.SecureRandom` for every encrypted field. Nonces are never reused.
- **Tenant Key Derivation:** Master vault key (`VAULT_ENCRYPTION_KEY_BASE64`) derives individual, tenant-isolated sub-keys for each user using:
  $$\text{SubKey} = \text{HMAC-SHA256}(\text{RootVaultKey}, \text{"SecureVault/credential/v1/"} \parallel \text{UserUUID})$$
- **Additional Authenticated Data (AAD) Binding:** Every credential encryption operation binds context metadata:
  $$\text{AAD} = \text{"SecureVault/credential/v1/"} \parallel \text{OwnerUUID} \parallel \text{"/"} \parallel \text{CredentialUUID}$$
  This cryptographically guarantees that ciphertext cannot be copied or transplanted between different accounts or records.

### 2.2 Password Hashing & Side-Channel Defense
- **BCrypt:** Master user passwords are encrypted using salted BCrypt with recommended work factors.
- **72-Byte Truncation Guard:** Inputs are verified against a strict 72-byte ceiling to eliminate BCrypt prefix-truncation vulnerabilities.
- **Synthetic BCrypt Calculation:** In authentication lookups where a username does not exist, the backend executes a synthetic BCrypt verification against a pre-computed dummy hash (`dummyHash`). This normalizes server response times and prevents username enumeration via side-channel timing analysis.

### 2.3 TOTP MFA Seed Encryption
- Authenticator seeds are encrypted at rest using AES-256-GCM with sub-keys derived from an isolated `MFA_ENCRYPTION_KEY_BASE64`.

---

## 3. Network & Edge Security

### 3.1 Reverse Proxy & IP Spoofing Protections
To prevent attackers from spoofing their IP address via fabricated `X-Forwarded-For` HTTP headers:
- `ClientIpResolver` inspects incoming connection sockets against `security.trusted-proxy-cidrs` (`127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16`).
- `X-Forwarded-For` headers are only trusted if the immediate upstream client matches a designated trusted proxy CIDR. Untrusted connections fall back strictly to the remote socket IP address.

### 3.2 Outbound Email Security over HTTPS (Port 443)
To overcome cloud provider SMTP blocking and prevent plaintext SMTP eavesdropping or STARTTLS stripping:
- Transactional MFA verification codes are transmitted over authenticated HTTPS REST APIs (**Brevo API v3** / **Resend API v1**).
- Plaintext credentials and master passwords are never included in outbound email communications.

### 3.3 Strict Rate Limiting & Denial-of-Service Defense
- **Per-IP Rate Limiting:** In-memory token bucket filters restrict `/api/login` to a maximum of 30 requests per minute and `/api/registration` to 15 requests per minute.
- **Concurrency Caps:** A semaphore restricts concurrent in-flight authentication operations to 16 simultaneous requests to defend against Slowloris and thread pool exhaustion.
- **Payload Constraints:** Authentication request body sizes are strictly capped at 8 KiB.
- **Account Lockouts:** 5 consecutive failed login attempts trigger an automatic 15-minute account lockout.

---

## 4. Server-Side Encryption Disclosure

> [!IMPORTANT]
> **Server-Side Authenticated Encryption Notice:**
> SecureVault utilizes **Server-Side Authenticated Encryption (SSE)**.
> All vault data is encrypted before writing to PostgreSQL and decrypted on-the-fly for authorized authenticated sessions. However, encryption keys and runtime memory reside on the host application server. Operators possessing direct access to server memory, runtime container environment variables, and root encryption keys possess the technical capability to decrypt data.
> Organizations requiring zero-knowledge architectures must implement client-side key derivation and client-side encryption before payload transmission.

---

## 5. Vulnerability Reporting & Responsible Disclosure

We take security vulnerabilities seriously and appreciate responsible disclosure.

If you discover a security flaw or vulnerability within SecureVault:
1. **Do NOT open a public GitHub issue.**
2. Send an encrypted or confidential report directly to: **rabishankarroy04@gmail.com**
3. Include detailed reproduction steps, impact assessment, and proof-of-concept code where applicable.
4. Please allow reasonable time (30–90 days) for review, remediation, and verification before disclosing publicly.
