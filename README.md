# SecureVault

[![Spring Boot](https://img.shields.io/badge/Spring%20Boot-3.4.x-6DB33F?logo=springboot&logoColor=white)](https://spring.io/projects/spring-boot)
[![Java](https://img.shields.io/badge/Java-17%2B-ED8B00?logo=openjdk&logoColor=white)](https://www.oracle.com/java/)
[![React](https://img.shields.io/badge/React-19.x-61DAFB?logo=react&logoColor=black)](https://react.dev/)
[![Vite](https://img.shields.io/badge/Vite-8.x-646CFF?logo=vite&logoColor=white)](https://vitejs.dev/)
[![PostgreSQL](https://img.shields.io/badge/PostgreSQL-16%2B-4169E1?logo=postgresql&logoColor=white)](https://www.postgresql.org/)
[![Security](https://img.shields.io/badge/Encryption-AES--256--GCM-blueviolet)](#cryptographic-architecture)
[![Status](https://img.shields.io/badge/Deployment-Live-success)](https://securevault-frontend-6pzq.onrender.com)

**SecureVault** is an enterprise-grade, high-assurance credential management and secure sharing platform. Built with a **Spring Boot** backend and a **React + Vite** frontend, SecureVault delivers military-grade **AES-256-GCM** server-side authenticated encryption, multi-factor authentication (Authenticator TOTP & Email challenges), zero-leak external credential sharing, real-time threat monitoring, and granular administrative audit logging with reverse-proxy real IP resolution.

---

## 🌐 Live Production Demo

Experience the live deployment hosted on Render:

- **Frontend Application:** [https://securevault-frontend-6pzq.onrender.com](https://securevault-frontend-6pzq.onrender.com)
- **Backend API & Health Check:** [https://securevault-backend-8k4c.onrender.com/api/health](https://securevault-backend-8k4c.onrender.com/api/health)

---

## 📑 Table of Contents

- [Core Capabilities](#-core-capabilities)
- [System Architecture](#-system-architecture)
- [Cryptographic Architecture](#-cryptographic-architecture)
- [Tech Stack](#-tech-stack)
- [Local Development Quickstart](#-local-development-quickstart)
  - [Prerequisites](#prerequisites)
  - [1. Configure Environment Secrets](#1-configure-environment-secrets)
  - [2. Start Services with Docker Compose (Mailpit)](#2-start-services-with-docker-compose-mailpit)
  - [3. Start the Frontend](#3-start-the-frontend)
- [Production Cloud Deployment](#-production-cloud-deployment)
  - [Render Blueprint (One-Click)](#render-blueprint-one-click)
  - [Cloud Email Delivery (Brevo / Resend HTTPS API)](#cloud-email-delivery-brevo--resend-https-api)
  - [Trusted Proxies & Real Client IP Resolution](#trusted-proxies--real-client-ip-resolution)
- [Admin Console & Threat Analysis](#-admin-console--threat-analysis)
- [Testing & Quality Assurance](#-testing--quality-assurance)
- [Security & Compliance Documentation](#-security--compliance-documentation)
- [License](#-license)

---

## ✨ Core Capabilities

### 🔐 1. Multi-Factor Authentication (MFA) & Risk-Based Security
- **TOTP Authenticator Enrollment:** Local QR code generation with standard authenticator app support (Google Authenticator, Microsoft Authenticator, 1Password, Authy). TOTP seeds are encrypted at rest with AES-256-GCM.
- **Risk-Based Step-Up Verification:** Unrecognized devices, new IP locations, or accounts without TOTP automatically trigger an email login challenge with a cryptographically secure 6-digit OTP code.
- **Multi-Transport Email Delivery:** Resilient transactional email pipeline supporting **Brevo REST API** and **Resend REST API** (over HTTPS port 443) with automatic fallback to standard SMTP and secure server logs.

### 🛡️ 2. Encrypted Vault Management
- **Full Credential Lifecycle:** Secure CRUD operations for logins, passwords, URLs, custom notes, categories, and favorites.
- **Password Health & Breach Analysis:** Integration with the **Have I Been Pwned (HIBP)** API using strict **$k$-Anonymity** (only the first 5 hexadecimal characters of the SHA-1 hash leave the server). Plaintext passwords and full hashes are never exposed externally.
- **Client Masking & Copy Safeguards:** Credentials remain masked by default in the UI until explicitly revealed or copied via clipboard write safeguards.

### 🔗 3. Zero-Leak External & Internal Credential Sharing
- **Internal User-to-User Sharing:** Share credentials directly with registered team members with selectable read-only permissions and revocation history.
- **External Time-Limited Sharing:** Send secure, encrypted invitations to external recipients via email without requiring recipient registration:
  - Configurable expiration (from 1 hour to 7 days).
  - Optional **One-Time Retrieval** (access token self-destructs immediately after retrieval).
  - Recipient email OTP verification challenge before disclosure.
  - Dedicated zero-dependency recipient portal (`external.html`) that excludes third-party fonts, analytics, and telemetry.
  - Granular owner revocation at any point.

### 📊 4. Enterprise Admin Console & Threat Analysis
- **Unified Portal:** Both standard users (`ROLE_USER`) and administrators (`ROLE_ADMIN`) sign in through a single intuitive interface with role-aware route isolation.
- **Real-Time Threat Monitoring:** Track failed login spikes, brute-force attempts, suspicious IP patterns, and account lockout counters.
- **Tamper-Resilient Audit Trail:** Searchable, immutable event logs recording user registrations, logins, credential modifications, and share retrievals. Includes real client public IP resolution behind cloud reverse proxies and one-click CSV / Excel export.
- **System Health:** Live monitoring of database connection pool stats, memory utilization, active sessions, and outbound email transport status.

---

## 🏛 System Architecture

```
                                 ┌────────────────────────────────────────────────────────┐
                                 │                User Browser / Client                   │
                                 └───────────┬────────────────────────────────┬───────────┘
                                             │ HTTPS                          │ HTTPS
                                             ▼                                ▼
                       ┌───────────────────────────────┐            ┌───────────────────┐
                       │   Frontend (React 19 / Vite)  │            │ External Share UI │
                       │    Render Static Site / CDN   │            │  (external.html)  │
                       └──────────────┬────────────────┘            └─────────┬─────────┘
                                      │                                       │
                                      │ /api/* (Reverse Proxy / HTTPS)        │
                                      ▼                                       ▼
                       ┌────────────────────────────────────────────────────────────────┐
                       │               Backend (Spring Boot 4 / Java 17)                │
                       │    Render Web Service / Containerized Runtime (Port 8080)       │
                       └───────┬───────────────────────┬────────────────────────┬───────┘
                               │                       │                        │
                               ▼                       ▼                        ▼
                    ┌─────────────────────┐ ┌─────────────────────┐  ┌─────────────────────┐
                    │ PostgreSQL Database │ │   Brevo/Resend API  │  │   HIBP Pwned API    │
                    │   AES-256 Encrypted │ │  HTTPS REST (p.443) │  │  k-Anonymity (SHA-1)│
                    │   Role: securevault │ │ Email OTP & Shares  │  │   Password Health   │
                    └─────────────────────┘ └─────────────────────┘  └─────────────────────┘
```

---

## 🔒 Cryptographic Architecture

SecureVault implements **Server-Side Authenticated Encryption (SSE)** designed under strict defense-in-depth principles:

| Component | Primitive / Standard | Implementation Details |
| :--- | :--- | :--- |
| **Vault Credentials** | **AES-256-GCM** | 96-bit unique cryptographic IV/nonce per record, 128-bit authentication tag. |
| **Tenant Key Derivation** | **HMAC-SHA256** | Per-user isolated sub-keys derived from root `VAULT_ENCRYPTION_KEY_BASE64` using `HMAC-SHA256("SecureVault/credential/v1/" + owner_uuid)`. |
| **Ciphertext Integrity** | **AAD Binding** | Additional Authenticated Data bound to `("SecureVault/credential/v1/" + owner + "/" + credential)`. Prevents ciphertext transplantation across accounts. |
| **Master Passwords** | **BCrypt** | Salted password hashing with a strict 72-byte ceiling check to prevent truncation attacks. |
| **MFA Seeds** | **AES-256-GCM** | TOTP secret keys encrypted at rest using isolated `MFA_ENCRYPTION_KEY_BASE64`. |
| **Session Security** | **JWT + SHA-256** | HMAC-SHA384/512 signed stateless tokens. Raw tokens are never stored; database stores only SHA-256 hashes (`SessionTokenUtils.fingerprint()`). |
| **Timing Attack Mitigation** | **Synthetic Hashes** | Unregistered username lookups execute a synthetic BCrypt calculation (`dummyHash`) to normalize timing profiles. |

---

## 🛠 Tech Stack

- **Backend:** Spring Boot 4.x / 3.4.x, Java 17, Spring Security 6, Spring Data JDBC, HikariCP, Nimbus JOSE JWT, Apache Commons Codec.
- **Frontend:** React 19, Vite 8, Tailwind CSS, Lucide React, Canvas Confetti.
- **Database:** PostgreSQL 16+ (Managed Cloud or Docker).
- **Email Delivery:** Brevo HTTP REST API v3, Resend REST API v1, Spring Mail (SMTP/STARTTLS), Mailpit (Local Test).
- **Deployment & Containers:** Docker, Docker Compose, Render Blueprint (`render.yaml`), Railway.

---

## 💻 Local Development Quickstart

### Prerequisites
- [Docker Desktop](https://www.docker.com/) with Linux containers and Compose 2.24.4+
- [Java 17+](https://adoptium.net/) and [Maven 3.9+](https://maven.apache.org/)
- [Node.js 22.12+](https://nodejs.org/) (LTS recommended) and `npm`

### 1. Configure Environment Secrets

From the repository root:

```powershell
Copy-Item .env.example .env
```

Generate three distinct 48-byte cryptographically random base64 strings and paste them into `.env`:

```powershell
# In PowerShell:
$bytes = New-Object byte[] 48
$rng = [Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes)
$rng.Dispose()
```

Fill the required keys in `.env`:
- `POSTGRES_PASSWORD`: Strong database password.
- `SECUREVAULT_DB_APP_PASSWORD`: Application role password.
- `JWT_SECRET_BASE64`: Generated 48-byte key.
- `MFA_ENCRYPTION_KEY_BASE64`: Generated 48-byte key.
- `VAULT_ENCRYPTION_KEY_BASE64`: Generated 48-byte key.

### 2. Start Services with Docker Compose (Mailpit)

Start PostgreSQL, the Spring Boot backend, and local Mailpit:

```powershell
$base = @('-p', 'securevaultpersonal', '-f', 'docker-compose.yml', '-f', 'compose.local.yml')
docker compose --env-file .env @base -f compose.mailpit.yml up -d --build
```

- **Backend API:** [http://127.0.0.1:28080/api/health](http://127.0.0.1:28080/api/health)
- **Local Mailpit Web UI:** [http://127.0.0.1:28025](http://127.0.0.1:28025) (Captures all registration and OTP emails).

### 3. Start the Frontend

In a separate terminal:

```powershell
cd frontend
npm ci
$env:VITE_API_TARGET = "http://127.0.0.1:28080"
npm run dev -- --port 4300
```

Open [http://127.0.0.1:4300](http://127.0.0.1:4300) in your browser.

---

## ☁️ Production Cloud Deployment

### Render Blueprint (One-Click)

SecureVault includes an automated `render.yaml` Infrastructure-as-Code Blueprint that provisions the PostgreSQL database, Spring Boot API, and static React frontend in minutes:

1. Fork this repository to your GitHub account.
2. In the [Render Dashboard](https://dashboard.render.com), click **New +** $\rightarrow$ **Blueprint**.
3. Connect your repository and select branch `TEAM-3` (or `main`).
4. Enter the required environment secrets when prompted:
   - `BREVO_API_KEY`: Your Brevo API key (e.g., `xkeysib-...`).
   - `BREVO_FROM`: Your verified Brevo sender email.
   - Or `RESEND_API_KEY` & `RESEND_FROM`.
5. Click **Apply**. Render will automatically provision the managed database, build the containerized backend, and host the frontend static CDN.

For in-depth deployment walkthroughs, see [DEPLOYMENT.md](DEPLOYMENT.md).

### Cloud Email Delivery (Brevo / Resend HTTPS API)

Cloud hosting platforms (including Render Free tier) block outbound SMTP traffic on ports **25, 465, and 587**. SecureVault avoids SMTP blocks by routing transactional emails over **HTTPS REST APIs (port 443)**:

```
[Spring Boot EmailChallengeSender]
               │
               ├─► 1. Brevo REST API (HTTPS :443)  [Primary]
               │
               ├─► 2. Resend REST API (HTTPS :443) [Secondary]
               │
               ├─► 3. JavaMail SMTP (STARTTLS)     [Fallback / Local]
               │
               └─► 4. Secure Server Log Fallback   [Diagnostic Mode]
```

To configure Brevo:
```properties
BREVO_API_KEY=xkeysib-xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
BREVO_FROM=your-verified-email@domain.com
```

### Trusted Proxies & Real Client IP Resolution

In cloud environments (Render, Cloudflare, AWS ALB), client requests pass through reverse proxies. SecureVault features intelligent proxy header inspection via `ClientIpResolver`:

```properties
server.forward-headers-strategy=framework
security.trusted-proxy-cidrs=127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```

This ensures that the **Admin Audit Trail** logs true public IP addresses (e.g., `103.xxx.xxx.xxx`) instead of internal proxy loopbacks (`0:0:0:0:0:0:0:1`).

---

## 👥 Admin Console & Threat Analysis

### Promoting the First Administrator

SecureVault includes automatic admin bootstrapping for the first registered user when configured, or manual promotion via SQL:

```sql
BEGIN;
INSERT INTO user_roles(user_id, role_id)
SELECT u.id, r.id 
FROM users u 
CROSS JOIN roles r
WHERE u.username = 'your_username' AND r.role_name = 'ROLE_ADMIN'
ON CONFLICT DO NOTHING;
COMMIT;
```

Once promoted:
1. Sign in to the frontend.
2. Click **Admin Console** in the top navigation.
3. Access **Users & Roles**, **Threat Analysis**, **Audit Trail**, **Sharing Activity**, and **System Health**.

---

## 🧪 Testing & Quality Assurance

Run the comprehensive test suites across backend and frontend:

```powershell
# Backend unit & integration tests
mvn -f backend/pom.xml clean test

# Frontend component & E2E tests
cd frontend
npm test -- --maxWorkers=2 --testTimeout=20000

# Production build verification
npm run build
```

---

## 📄 Security & Compliance Documentation

- [SECURITY.md](SECURITY.md) — Comprehensive security policy, cryptographic threat model, and vulnerability reporting procedures.
- [PRIVACY_POLICY.md](PRIVACY_POLICY.md) — Data collection, encryption standards, k-anonymity breach checking disclosures, and retention policies.
- [TERMS_OF_SERVICE.md](TERMS_OF_SERVICE.md) — Terms of service, acceptable use policies, and administrative boundaries.
- [DEPLOYMENT.md](DEPLOYMENT.md) — Comprehensive cloud operations guide for Render and Railway.

---

## 📄 License

This project is licensed under the [MIT License](LICENSE).
