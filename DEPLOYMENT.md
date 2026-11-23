# SecureVault Cloud Deployment Guide (Render & Railway)

This guide provides step-by-step instructions for deploying SecureVault to **Render.com** (via automated Blueprint) and **Railway.app**.

---

## Architecture Overview

```
                      ┌────────────────────────────────────────┐
                      │            Browser Client              │
                      └──────────────────┬─────────────────────┘
                                         │ (HTTPS)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │       Frontend (Vite / React)          │
                      │   Render Static Site / CDN (Free)      │
                      └──────────────────┬─────────────────────┘
                                         │ /api/* (Proxied)
                                         ▼
                      ┌────────────────────────────────────────┐
                      │      Backend (Spring Boot 4 / Java 17) │
                      │         Render Web Service / Docker    │
                      └───────┬────────────────────────┬───────┘
                              │                        │
                              ▼                        ▼
           ┌────────────────────────────┐    ┌─────────────────────────┐
           │   Managed PostgreSQL 16    │    │       Gmail SMTP        │
           │      Database Instance     │    │  (2-Step Verification)  │
           └────────────────────────────┘    └─────────────────────────┘
```

---

## Option A: Deploy on Render.com (Recommended)

SecureVault includes an automated `render.yaml` Infrastructure-as-Code Blueprint that provisions the Database, Spring Boot backend, and React frontend in a single step.

### Step 1: Open Render Dashboard
1. Go to [https://dashboard.render.com](https://dashboard.render.com).
2. Sign in with your GitHub account (`rabishankarroy04-svg`).

### Step 2: Create a New Blueprint
1. Click the **New +** button in the top navigation bar and select **Blueprint**.
2. Select your repository: `rabishankarroy04-svg/password_vault`.
3. Set the Branch to `3-mangal-clean` (or `TEAM-3`).
4. Click **Connect**.

### Step 3: Enter Secrets
Render will detect `render.yaml` and prompt you for the uncommitted secrets:
- `SPRING_MAIL_USERNAME`: Your Gmail address (e.g. `rabishankarroy04@gmail.com`).
- `SPRING_MAIL_PASSWORD`: Your 16-character Google App Password (without spaces).
- `SECUREVAULT_MAIL_FROM`: Your Gmail address (e.g. `rabishankarroy04@gmail.com`).

All base64 encryption keys (`JWT_SECRET_BASE64`, `MFA_ENCRYPTION_KEY_BASE64`, `VAULT_ENCRYPTION_KEY_BASE64`) and database credentials are automatically generated and linked by Render!

### Step 4: Click "Apply"
1. Render will provision:
   - `securevault-postgres` (PostgreSQL Database)
   - `securevault-backend` (Spring Boot API container)
   - `securevault-frontend` (Static React App with automated `/api/*` rewrites)
2. When the build finishes, open the `securevault-frontend` URL (e.g., `https://securevault-frontend.onrender.com`).

---

## Option B: Deploy on Railway.app

If you prefer Railway:

### Step 1: Create a Railway Project
1. Go to [https://railway.app](https://railway.app) and log in with GitHub.
2. Click **New Project** $\rightarrow$ **Provision PostgreSQL**.

### Step 2: Deploy the Backend
1. In the project canvas, click **Create** $\rightarrow$ **GitHub Repo**.
2. Select `rabishankarroy04-svg/password_vault`.
3. Go to the Service Settings $\rightarrow$ **Source**:
   - Set **Root Directory** to `/backend`.
   - Railway will detect the `Dockerfile`.
4. Go to **Variables** and add:
   - `SERVER_ADDRESS`: `0.0.0.0`
   - `PORT`: `8080`
   - `SPRING_SQL_INIT_MODE`: `always`
   - `SPRING_DATASOURCE_URL`: `${{Postgres.DATABASE_URL}}`
   - `SPRING_DATASOURCE_USERNAME`: `${{Postgres.PGUSER}}`
   - `SPRING_DATASOURCE_PASSWORD`: `${{Postgres.PGPASSWORD}}`
   - `JWT_SECRET_BASE64`: *(Generate 48-byte base64 random key)*
   - `MFA_ENCRYPTION_KEY_BASE64`: *(Generate 48-byte base64 random key)*
   - `VAULT_ENCRYPTION_KEY_BASE64`: *(Generate 48-byte base64 random key)*
   - `SPRING_MAIL_HOST`: `smtp.gmail.com`
   - `SPRING_MAIL_PORT`: `587`
   - `SPRING_MAIL_USERNAME`: your Gmail address
   - `SPRING_MAIL_PASSWORD`: your 16-character Google App Password
   - `SECUREVAULT_MAIL_FROM`: your Gmail address
   - `SECUREVAULT_CORS_ALLOWED_ORIGINS`: `${{Frontend.RAILWAY_PUBLIC_DOMAIN}}`
   - `SECUREVAULT_EXTERNAL_BASE_URL`: `https://${{Frontend.RAILWAY_PUBLIC_DOMAIN}}`

### Step 3: Deploy the Frontend
1. Click **Create** $\rightarrow$ **GitHub Repo** $\rightarrow$ select `password_vault`.
2. In Service Settings $\rightarrow$ **Source**:
   - Set **Root Directory** to `/frontend`.
3. Under **Networking**, click **Generate Domain**.

---

## First Account Admin Bootstrapping

SecureVault is configured so that the **first user who registers is automatically assigned both `ROLE_USER` and `ROLE_ADMIN`**.

1. As soon as deployment finishes, visit your frontend URL.
2. Click **Create an Account**.
3. Register your primary administrator username, email, and password.
4. Your account is immediately created as the root administrator.
5. All subsequent registrations are standard user accounts.
