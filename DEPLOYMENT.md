# SecureVault Cloud Deployment & Operations Guide

This guide provides end-to-end instructions for deploying, configuring, and operating **SecureVault** on cloud platforms, with primary focus on **Render.com** (via automated Infrastructure-as-Code Blueprint) and **Railway.app**.

---

## 🌐 Live Production References

- **Frontend Static Site:** [https://securevault-frontend-6pzq.onrender.com](https://securevault-frontend-6pzq.onrender.com)
- **Backend API Service:** [https://securevault-backend-8k4c.onrender.com](https://securevault-backend-8k4c.onrender.com)
- **Backend Health Check:** [https://securevault-backend-8k4c.onrender.com/api/health](https://securevault-backend-8k4c.onrender.com/api/health)

---

## 🏗 Architecture & Cloud Topology

```
                       ┌────────────────────────────────────────────────────────┐
                       │                     User Browser                       │
                       └───────────────────┬────────────────────────────────────┘
                                           │ HTTPS (Port 443)
                                           ▼
                       ┌────────────────────────────────────────────────────────┐
                       │             Render CDN / Static Site Host              │
                       │           (securevault-frontend-6pzq)                  │
                       └───────────────────┬────────────────────────────────────┘
                                           │ /api/* (Proxied with X-Forwarded-For)
                                           ▼
                       ┌────────────────────────────────────────────────────────┐
                       │              Render Web Service (Docker)               │
                       │            (securevault-backend-8k4c)                  │
                       │          Spring Boot 4 Runtime (Port 8080)             │
                       └───────┬───────────────────────┬────────────────────────┘
                               │                       │
                               ▼                       ▼
                    ┌─────────────────────┐ ┌───────────────────────────────────┐
                    │ Managed PostgreSQL  │ │ Outbound Email Transport (HTTPS)  │
                    │   Instance (v16)    │ │   1. Brevo REST API (:443)        │
                    │   Role: securevault │ │   2. Resend REST API (:443)       │
                    │   Internal Private  │ │   3. Fallback: Diagnostic Log     │
                    └─────────────────────┘ └───────────────────────────────────┘
```

---

## 🚀 Option A: Deploy on Render.com (Recommended)

Render provides zero-config deployment using the repository's root [`render.yaml`](render.yaml) blueprint file.

### Step 1: Link Repository in Render
1. Navigate to the [Render Dashboard](https://dashboard.render.com).
2. Click **New +** $\rightarrow$ **Blueprint**.
3. Select the repository: `rabishankarroy04-svg/password_vault`.
4. Choose the target branch (e.g., `TEAM-3` or `3-mangal-clean`).

### Step 2: Configure Environment Secrets
Render will detect `render.yaml` and provision three synchronized services:
1. `securevault-postgres` (PostgreSQL Database)
2. `securevault-backend` (Web Service / Docker container)
3. `securevault-frontend` (Static Site / Vite build)

During initial setup, configure the following environment secrets in the Render UI:

| Variable | Recommended Value / Description | Required? |
| :--- | :--- | :--- |
| `BREVO_API_KEY` | Your Brevo REST API key (`xkeysib-...`) | **Recommended** |
| `BREVO_FROM` | Your verified Brevo sender email (e.g. `rabishankarroy04@gmail.com`) | **Recommended** |
| `RESEND_API_KEY` | Your Resend API key (`re_...`) | Optional fallback |
| `RESEND_FROM` | Sender address (e.g. `onboarding@resend.dev` or verified domain) | Optional fallback |
| `SPRING_MAIL_USERNAME` | Gmail address (if using standard SMTP) | Optional |
| `SPRING_MAIL_PASSWORD` | 16-character Google App Password | Optional |
| `JWT_SECRET_BASE64` | *Render auto-generates random 48-byte string* | Auto |
| `MFA_ENCRYPTION_KEY_BASE64` | *Render auto-generates random 48-byte string* | Auto |
| `VAULT_ENCRYPTION_KEY_BASE64` | *Render auto-generates random 48-byte string* | Auto |
| `SECURITY_TRUSTED_PROXY_CIDRS` | `127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16` | Auto |

### Step 3: Deploy & Verify
1. Click **Apply Blueprint**.
2. Render will spin up the database, execute `DatabaseSchemaInitializer`, build the container, and publish the frontend.
3. Open your frontend URL to access the live app.

---

## ✉️ Critical: Cloud Outbound Email Delivery

> [!IMPORTANT]
> **SMTP Port Blocking in Cloud Providers:**
> Render Free tier and many cloud serverless environments block outbound connections on standard SMTP ports (**25, 465, and 587**) to combat spam abuse.
> Direct connections to `smtp.gmail.com:587` will fail with `SocketTimeoutException: Connect timed out`.

To guarantee reliable delivery of MFA codes and external share invitations, SecureVault incorporates an **intelligent multi-transport dispatch hierarchy** in `EmailChallengeSender.java`:

### 1. Brevo REST API (Primary - HTTPS Port 443)
- Transmits messages directly via `https://api.brevo.com/v3/smtp/email` over TLS.
- Unlike Resend's sandbox mode, Brevo permits delivery to any external recipient address without mandatory custom domain verification.
- **Config:** Set `BREVO_API_KEY` and `BREVO_FROM`.

### 2. Resend REST API (Secondary - HTTPS Port 443)
- Transmits messages via `https://api.resend.com/emails` over TLS.
- Note: In free/sandbox mode without a verified domain, Resend only allows sending to the account holder's registered email address.
- **Config:** Set `RESEND_API_KEY` and `RESEND_FROM`.

### 3. JavaMail SMTP (Local / Self-Hosted Fallback)
- Utilized in local development (with Docker Mailpit) or self-hosted VMs where outbound SMTP ports are unobstructed.

### 4. Diagnostic Server Log Output
- If cloud network restrictions prevent API delivery or keys are absent, the 6-digit MFA challenge code is securely output to backend logs:
  ```
  SECUREVAULT MFA SIGN-IN CODE FOR user@example.com: [935498]
  ```

---

## 🌐 Reverse Proxy Configuration & Real Client IP Resolution

When deployed behind cloud routers (Render, Cloudflare, NGINX), incoming requests pass through proxy layers. Without proper configuration, all client events in the **Admin Audit Trail** would display the internal loopback address (`0:0:0:0:0:0:0:1` or `127.0.0.1`).

SecureVault includes automated reverse-proxy header evaluation:

### 1. Spring Framework Forwarded Headers
In `application.properties` and `render.yaml`:
```properties
server.forward-headers-strategy=framework
```

### 2. Trusted Proxy CIDRs
`ClientIpResolver.java` validates whether the immediate connection originates from a trusted internal proxy CIDR. If trusted, it extracts the original client IP from `X-Forwarded-For`:
```properties
security.trusted-proxy-cidrs=127.0.0.1/8,::1/128,10.0.0.0/8,172.16.0.0/12,192.168.0.0/16
```
This enables real client public IP addresses to be attributed to security events and audit records.

---

## ⚡ Vite 8 & Linux Rolldown Native Binding on Render

When deploying Vite 8 / Rolldown frontends on Linux build servers (such as Render Ubuntu build instances) from lockfiles created on Windows:
1. Set the Node runtime version:
   ```yaml
   NODE_VERSION: 22.14.0
   ```
2. Include the Linux native binding package in the build pipeline:
   ```bash
   npm install --no-save @rolldown/binding-linux-x64-gnu@1.2.15 && npm run build
   ```
This prevents `Cannot find native binding @rolldown/binding-linux-x64-gnu` runtime errors during compilation.

---

## 🗄 Database Initialization & Schema Reset

SecureVault includes an automated JDBC schema bootstrap (`DatabaseSchemaInitializer.java`) that executes upon startup. It creates all tables, indices, roles, and constraints without requiring external migration tooling.

### Emergency Schema Reset Flag
If database tables become corrupted or a clean slate is required on a managed database where `DROP DATABASE` is not permitted:
1. In the Render Backend Environment variables, set:
   ```
   SECUREVAULT_SCHEMA_RESET=true
   ```
2. Trigger a redeploy. The backend will drop all existing application tables with `CASCADE`, re-execute `schema.sql`, and restore a clean schema state.
3. **Important:** Remove or set `SECUREVAULT_SCHEMA_RESET=false` after restart to prevent re-initializing on future boots.

---

## 👑 First Administrator Bootstrapping

SecureVault supports automatic or manual promotion of administrator accounts.

### Manual SQL Promotion
To elevate an active user to `ROLE_ADMIN`, run the following SQL against your PostgreSQL instance:

```sql
BEGIN;
SELECT id, username, email FROM users WHERE username = 'royrabi';

INSERT INTO user_roles (user_id, role_id)
SELECT u.id, r.id 
FROM users u 
CROSS JOIN roles r 
WHERE u.username = 'royrabi' AND r.role_name = 'ROLE_ADMIN'
ON CONFLICT DO NOTHING;

COMMIT;
```

Once promoted, log in via the unified frontend and access the **Admin Console** tab in the top navigation.
