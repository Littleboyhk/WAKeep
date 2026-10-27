# <img src="public/whatsapp-logo.svg" width="36" height="36" align="center" alt="WhatsApp"> WAKeep

<p align="center">
  <strong>24/7 Persistent WhatsApp Web Companion Gateway & Live Dashboard</strong><br>
  <em>Never get logged out of WhatsApp Web again. No camera required. Zero data collection. 100% Free forever.</em>
</p>

<p align="center">
  <img src="https://img.shields.io/badge/WhatsApp-25D366?style=for-the-badge&logo=whatsapp&logoColor=white" alt="WhatsApp">
  <a href="https://wakeep.onrender.com"><img src="https://img.shields.io/badge/Live%20Demo-wakeep.onrender.com-10b981?style=for-the-badge&logo=render&logoColor=white" alt="Live Demo"></a>
  <a href="https://github.com/Littleboyhk/WAKeep/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-MIT-blue?style=for-the-badge" alt="MIT License"></a>
  <img src="https://img.shields.io/badge/Platform-Node.js%2022%20LTS-339933?style=for-the-badge&logo=node.js&logoColor=white" alt="Node Version">
  <img src="https://img.shields.io/badge/Security-AES--256--GCM%20Vault-0ea5e9?style=for-the-badge&logo=shield" alt="AES-256-GCM Vault">
  <img src="https://img.shields.io/badge/India%20Compliance-DPDP%20Act%202023-orange?style=for-the-badge" alt="DPDP Act 2023">
</p>

---

## 📖 Table of Contents
- [Why WAKeep Exists (The Problem Solved)](#-why-wakeep-exists-the-problem-solved)
- [How It Works in Simple Terms](#-how-it-works-in-simple-terms)
- [⚡ Quick Start: Use Without Coding (Zero Setup Required)](#-quick-start-use-without-coding-zero-setup-required)
- [🛠️ Self-Hosting Guide: Build Your Own Private Instance](#-self-hosting-guide-build-your-own-private-instance)
  - [Step 1: Set Up Free Database (Supabase)](#step-1-set-up-free-database-supabase)
  - [Step 2: Deploy to Free Cloud (Render)](#step-2-deploy-to-free-cloud-render)
  - [Step 3: Keep it Awake 24/7 (Cron-Job.org — Self-Hosters Only)](#step-3-keep-it-awake-247-cron-joborg--self-hosters-only)
- [🔒 Privacy & Indian Legal Compliance](#-privacy--indian-legal-compliance)
- [❓ Frequently Asked Questions (FAQ)](#-frequently-asked-questions-faq)
- [📡 API Reference (For Developers)](#-api-reference-for-developers)
- [📄 License & Disclaimer](#-license--disclaimer)

---

## 💡 Why WAKeep Exists (The Problem Solved)

Every day, millions of students, professionals, business owners, and shopkeepers in India use **WhatsApp Web** on their laptops and computers.

### The Pain Points:
1. **The Annoying 6-Hour / Idle Logout:** When you close your browser tab, turn off your laptop, or leave your desk, WhatsApp Web drops the session. You come back only to find a yellow banner: *"Phone not connected"* or a blank QR code asking you to scan again.
2. **Camera Hassle:** You are sitting in an office or a dark room and having to reach for your phone, unlock it, open settings, and aim a shaky camera at the screen.
3. **Cloud Sleep Cycles:** If you try hosting a standard WhatsApp bot on free cloud services like Render or Koyeb, the server restarts every few days, wiping the local hard drive and destroying your login session.

### The WAKeep Solution:
- 🛡️ **Permanent 24/7 Session:** Your login credentials are saved in an **AES-256-GCM encrypted database vault** that survives server restarts, cloud updates, and browser closures.
- 🏓 **Steady 25-Second Heartbeats:** Emits gentle background cryptographic keep-alive pings to WhatsApp servers, keeping your connection warm 24/7.
- 🔢 **8-Digit Phone Pairing Code:** Don't want to scan a QR code with your camera? Just enter your phone number, get an 8-character code, and link directly from your WhatsApp notifications!
- 🪶 **Under 50MB RAM:** Specially optimized to run forever on the **free tier** of Render, Koyeb, or Railway without spending a single rupee.

---

## 🧠 How It Works in Simple Terms

```
[ Your Mobile Phone ]
        |
        | (1) One-Time QR Scan or 8-Digit Pairing Code
        v
[ WAKeep Gateway (Render Cloud) ]
  - Emulates an Ubuntu Chrome Desktop Companion
  - Sends 25s NAT Heartbeats (keeps session active)
  - Memory footprint: ~35MB RAM
        |
        | (2) Client-Side AES-256-GCM Encryption
        v
[ Supabase PostgreSQL Vault ]
  - Stores encrypted session keys
  - mathematical zero-knowledge storage
        |
        ^ (3) Free Ping Every 5 Minutes (Automated on Live Host)
[ Cron-Job.org / Uptime Monitor ]
  - Prevents cloud free-tier from sleeping
```

When you link WAKeep, WhatsApp registers it as an authorized **Desktop Companion** (just like having a permanent Chrome browser running on an office computer). Even when your laptop is completely powered off, the cloud companion stays awake!

---

## ⚡ Quick Start: Use Without Coding (Zero Setup Required)

> [!IMPORTANT]
> ### 🚀 Zero Technical Setup for Website Users
> If you are using our live public website **[https://wakeep.onrender.com](https://wakeep.onrender.com)**:
> - ❌ You **DO NOT** need to set up any 5-minute ping, cron job, or external monitor.
> - ❌ You **DO NOT** need a Supabase, Render, or cron-job.org account.
> - ✅ **24/7 Keep-Alive is 100% Automated:** The server host automatically runs a continuous 5-minute keep-alive ping that keeps the cloud container and all active user sessions awake around the clock!
>
> Simply enter your session name, create a password (minimum 8 characters), and scan your QR code once.
>
> *(The 5-minute ping on cron-job.org described below is **strictly and exclusively** for developers who self-host on their own Render free tier).*

WAKeep features an **Isolated Multi-Session Architecture**:

### 1. Activating a New Session (For New Users):
1. Go to **[https://wakeep.onrender.com](https://wakeep.onrender.com)**.
2. Under **"Activate New Session"**, enter a unique session name or your phone number (e.g. `rahul` or `919876543210`).
3. Set your own private password (mandatory minimum 8 characters).
4. Click **"Generate My QR Code"** &rarr; Your own dedicated QR code (or 8-digit phone pairing code) will appear instantly.
5. Scan with WhatsApp (**Settings &rarr; Linked Devices &rarr; Link a Device**). Once linked, your session stays active 24/7!

### 2. Returning to Your Active Session:
1. Switch to **"Unlock Existing Session"**.
2. Enter your session name and your 8+ character password.
3. Click **"Unlock My Console"** to view live connection telemetry, test pings, and heartbeat status.

> [!TIP]
> Each session is encrypted with AES-256-GCM in the cloud vault. Different users' QR codes, credentials, and telemetry are completely isolated in separate rooms.

---

## 🛠️ Self-Hosting Guide: Build Your Own Private Instance

Want 100% control over your own personal server and database? You can deploy your private instance in less than 5 minutes for **$0.00 (Completely Free)**.

### Prerequisites (All Free):
- A [GitHub](https://github.com) account.
- A free [Supabase](https://supabase.com) account (for encrypted cloud database storage).
- A free [Render](https://render.com) account (for hosting the Node.js application).
- A free [cron-job.org](https://cron-job.org) account (to keep the free server awake 24/7).

---

### Step 1: Set Up Free Database (Supabase)

1. Go to [supabase.com](https://supabase.com) and click **Start your project** (Sign in with GitHub).
2. Click **New project**, choose a name (e.g. `wakeep-vault`), set a database password, and select region **South Asia (Mumbai)** or closest to you.
3. Once the project finishes creating (takes ~60 seconds), click **SQL Editor** from the left navigation menu.
4. Click **New query**, paste the following SQL code, and click **Run**:

```sql
-- Create encrypted credentials vault table
-- (WAKeep collects ZERO messages and only stores encrypted multi-device auth tokens)
CREATE TABLE IF NOT EXISTS wa_auth_vault (
  id TEXT PRIMARY KEY,
  encrypted_payload TEXT NOT NULL,
  created_at TIMESTAMPTZ DEFAULT NOW(),
  updated_at TIMESTAMPTZ DEFAULT NOW()
);
```

5. Go to **Project Settings** (gear icon) &rarr; **API**:
   - Copy your **Project URL** (`https://your-project.supabase.co`).
   - Copy your **service_role** secret API key (starts with `ey...`).

---

### Step 2: Deploy to Free Cloud (Render)

1. **Fork this Repository:** Click the **Fork** button at the top right of this GitHub page to copy it to your own GitHub account.
2. Go to [render.com](https://render.com) and log in.
3. Click the blue **New +** button &rarr; select **Web Service**.
4. Choose **Build and deploy from a Git repository**, connect your GitHub account, and select your forked `WAKeep` repository.
5. In the configuration page, set:
   - **Name:** `my-wakeep-gateway` (or any name you like)
   - **Region:** Singapore or closest to you
   - **Branch:** `main`
   - **Runtime:** `Node`
   - **Build Command:** `npm install && npm run build`
   - **Start Command:** `npm start`
   - **Instance Type:** `Free` (0.1 CPU, 512MB RAM)
6. Scroll down to **Environment Variables** and add:

| Key | Example Value | Notes |
|---|---|---|
| `NODE_ENV` | `production` | Enables production mode |
| `SUPABASE_URL` | `https://your-id.supabase.co` | From Supabase Project Settings |
| `SUPABASE_KEY` | `eyJhbGciOi...` | Supabase **service_role** secret key |
| `VAULT_SECRET_KEY` | `64-character hex key` | 32-byte AES key (see generator below) |
| `ADMIN_PASSWORD` | `YourSecret#2026` | Mandatory 8+ character password to unlock dashboard |
| `JWT_SECRET` | `random_secret_phrase_here` | Any long random string |

> [!TIP]
> **Need a 64-character hex key for `VAULT_SECRET_KEY`?**
> You can generate one in your browser console or terminal:
> ```bash
> node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
> ```

7. Click **Deploy Web Service**!
   Render will build and deploy your app in about 2 minutes. When finished, you will receive your own unique live web address (e.g., `https://my-wakeep-gateway.onrender.com`).

---

### Step 3: Keep it Awake 24/7 (Cron-Job.org — Self-Hosters Only)

> [!NOTE]
> **Who needs this step?**
> - **Website users (`wakeep.onrender.com`):** ❌ **NOT NEEDED.** The server administrator already runs an automated 5-minute keep-alive ping for all sessions on the website.
> - **Self-hosters (deploying on their own Render account):** ✅ **REQUIRED.** Render's free tier puts inactive websites to sleep after 15 minutes of inactivity unless you configure this free ping.

To keep your personal self-hosted WAKeep active 24/7 without paying anything:

1. Sign up for a free account at [cron-job.org](https://cron-job.org).
2. Click **Create Cronjob**:
   - **Title:** `WAKeep 24/7 Pinger`
   - **Address (URL):** `https://your-app-name.onrender.com/api/health`
   - **Execution Schedule:** Every 5 minutes (`*/5 * * * *`).
3. Click **Create**.
4. That's it! `cron-job.org` will send a tiny ping every 5 minutes, preventing Render from sleeping. Your gateway will remain online 24 hours a day, 365 days a year.

---

## 🔒 Privacy & Indian Legal Compliance

We designed WAKeep around strict privacy and legal compliance principles:

### 1. Zero Data Collection Guarantee
- **No Chat Interception:** We do NOT read, copy, or sell your WhatsApp chats, audio files, or media.
- **No Third-Party Analytics:** No Google Analytics, no Facebook Pixels, no advertising trackers.
- **Client-Side Encryption:** All credentials stored in Supabase are mathematically scrambled using **AES-256-GCM**. Even if someone hacks the database, the credentials cannot be decrypted without your private `VAULT_SECRET_KEY`.

### 2. Digital Personal Data Protection Act, 2023 (DPDP Act, India)
- Under the DPDP Act 2023, you (the user) remain the sole **Data Principal** of your communications.
- When self-hosted on your own Supabase instance, all data remains strictly within your private database boundary.

### 3. Department of Telecommunications (DoT) Compliance
- In 2024, the Indian Department of Telecommunications (DoT) dropped the mandatory fixed 6-hour automatic web logout rule in favor of risk-based anomaly detection.
- WAKeep uses a persistent desktop fingerprint (`Ubuntu Chrome`) and regular 25-second WebSocket keep-alives, avoiding suspicious IP jumping or irregular reconnects that trigger security flags.

---

## ❓ Frequently Asked Questions (FAQ)

<details>
<summary><strong>1. Does my mobile phone need to be connected to the internet all the time?</strong></summary>
<p>No! Because of WhatsApp's multi-device architecture, once you link WAKeep via QR or pairing code, the companion session runs completely independently on the cloud. Even if your phone runs out of battery or loses mobile data for hours, the cloud session stays authenticated.</p>
</details>

<details>
<summary><strong>2. Can the developers or anyone else read my private messages?</strong></summary>
<p>No. WAKeep is 100% open-source software under the MIT license. You can inspect every single line of code in this repository. All session tokens are encrypted with AES-256-GCM using your private key before being saved.</p>
</details>

<details>
<summary><strong>3. Will my WhatsApp account get banned?</strong></summary>
<p>No. WAKeep does NOT send automated bulk marketing spam, cold blasts, or unsolicited advertising. It operates strictly as a personal companion device using Baileys' native multi-device protocol with <code>markOnlineOnConnect: false</code> and stable desktop fingerprinting.</p>
</details>

<details>
<summary><strong>4. How do I disconnect or logout my WhatsApp from the server?</strong></summary>
<p>You have full control and can log out at any time through either of two ways:</p>
<ol>
  <li><strong>Directly from the Website Console:</strong> Click the red <strong>"Log Out Account"</strong> button in your dashboard. This immediately tells WhatsApp servers to unlink the session and completely purges all encrypted vault keys and metadata from the database.</li>
  <li><strong>From Your Smartphone:</strong> Open WhatsApp &rarr; <strong>Settings</strong> &rarr; <strong>Linked Devices</strong> &rarr; tap <strong>WAKeep</strong> &rarr; tap <strong>Log out</strong>. The connection will terminate immediately.</li>
</ol>
</details>

<details>
<summary><strong>5. How is my console secured against unauthorized visitors?</strong></summary>
<p>Every WAKeep instance is protected by a mandatory 8+ character password (<code>ADMIN_PASSWORD</code>) with built-in rate-limiting (maximum 15 attempts per 15 minutes to block brute-force attacks) and constant-time cryptographic verification (<code>crypto.timingSafeEqual</code>). You can configure your secret password anytime in your Render dashboard under the <strong>Environment</strong> tab.</p>
</details>

<details>
<summary><strong>6. If I activate my session on wakeep.onrender.com, do I need to set up a 5-minute ping or cron job?</strong></summary>
<p><strong>No, absolutely not!</strong> Zero setup is required. When you use <a href="https://wakeep.onrender.com">https://wakeep.onrender.com</a>, the cloud server is already kept awake 24/7 by an automated background keep-alive monitor maintained by the host. All user sessions running on the server inherit this 24/7 continuous uptime automatically. The 5-minute ping instructions (via cron-job.org) are strictly for developers who fork this repository to self-host on their own private Render free tier.</p>
</details>

---

## 📡 API Reference (For Developers)

WAKeep exposes clean, rate-limited REST endpoints for developers building personal automations:

| Method | Endpoint | Auth Required | Purpose |
|---|---|---|---|
| `GET` | `/api/health` | ❌ None (Public) | Keep-alive heartbeat & RAM monitor |
| `POST` | `/api/auth/login` | ❌ None (Rate-limited) | Verifies Admin PIN with constant-time equality and issues JWT |
| `GET` | `/api/auth/verify` | 🔑 Bearer Token | Verifies token validity |
| `GET` | `/api/session/status` | 🔑 Admin Auth | Returns uptime, RAM usage, and WhatsApp connection status |
| `POST` | `/api/session/pair` | 🔑 Bearer Auth | Requests 8-digit pairing code for an international phone number |
| `POST` | `/api/session/ping` | 🔑 Bearer Auth | Verifies 24/7 keep-alive connection & server telemetry |
| `POST` | `/api/session/logout` | 🔑 Bearer Auth | Unlinks WhatsApp device and purges all credentials from server |
| `POST` | `/api/session/reset` | 🔑 Bearer Auth | Clears the encrypted Supabase vault to prepare for fresh scan |
| `GET` | `/api/session/messages` | 🔑 Bearer Auth | Returns empty list (Zero Data Collection: No chat messages stored) |

---

## 📄 License & Disclaimer

- **License:** Released under the permissive [MIT License](LICENSE).
- **Trademark Notice:** This software is an independent, open-source project. WhatsApp is a registered trademark of Meta Platforms, Inc. This project is not affiliated with, endorsed by, or sponsored by WhatsApp or Meta. All trademarks belong to their respective owners.

<p align="center">
  <sub>Built with ❤️ for privacy-conscious WhatsApp users across India and worldwide.</sub>
</p>
