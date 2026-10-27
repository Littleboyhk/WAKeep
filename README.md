# WAKeep
### 24/7 Persistent WhatsApp Web Bridge & Live Control Dashboard

A production-ready, self-hosted, 24/7 WhatsApp Web session manager and live web chat console. Designed to operate on **free-tier cloud hosting** (Render, Koyeb, Railway) with **zero disk persistence required** and memory consumption strictly under **70MB RAM**.

Requires only a **one-time QR scan** or an **8-character phone pairing code**. After linking, your session keys are encrypted with **AES-256-GCM** and vaulted in Supabase PostgreSQL, keeping your session alive indefinitely across container restarts and server redeployments.

---

## The Architecture & Core Problems Solved

### 1. Ephemeral Cloud Storage Survival
Free cloud containers wipe local disk storage on every restart or rebuild. Standard Baileys setups store credentials in `auth_info_baileys/` on the local filesystem, which causes session loss and demands frequent re-scanning.
- **Solution:** A custom, high-performance Supabase Auth State adapter (`src/lib/supabaseAuthState.ts`).
- **Cryptographic Security:** Every credential and signal key is encrypted using `AES-256-GCM` with a 32-byte secret key before transmission to Supabase.
- **Debounced Batch Writes:** Pre-keys generated during initial handshake are debounced in memory and committed in batches to prevent hitting Supabase API rate limits.

### 2. Preventing Idle Disconnects & Mobile Push Silencing
- **NAT Keep-Alive:** Baileys socket maintains active WebSocket heartbeats (`keepAliveIntervalMs: 25000`) to prevent intermediate firewall timeouts.
- **Push Notification Preservation:** `markOnlineOnConnect: false` ensures your primary mobile device rings and receives notifications without disruption.
- **Desktop Signature Spoofing:** Emulates a stable desktop browser (`['Ubuntu', 'Chrome', '128.0.6613.119']`) to prevent anomaly detection flags.
- **RAM Footprint:** Disables full history sync (`syncFullHistory: false`), keeping active Node heap usage under 35MB (total RSS < 70MB).

### 3. Single-Port Free Cloud Deployment
Free cloud tiers provide only 1 external public port:
- Express backend, REST API, Socket.IO real-time stream, and dark-mode Tailwind dashboard run unified on a single port.
- Includes a public `/api/health` ping endpoint for free external cron services (`cron-job.org` / `UptimeRobot`), preventing free-tier sleep cycles.

---

## System Overview

```
+--------------------------------------------------------------+
|                    Your Primary Phone                        |
|             (WhatsApp App -> Linked Devices)                 |
+------------------------------+-------------------------------+
                               |
                   One-Time QR or 8-Digit Code
                               |
                               v
+--------------------------------------------------------------+
|                    WAKeep (Cloud Container)                  |
|                                                              |
|   +-------------------+    +-----------------------------+   |
|   |  Socket Manager   |    |      Express & Socket.io    |   |
|   |  - Keep-Alive 25s |    |  - PIN Protection Middleware|   |
|   |  - Desktop Spoof  |    |  - Keep-Alive (/api/health) |   |
|   |  - Under 70MB RAM |    |  - Dark Dashboard Web UI    |   |
|   +---------+---------+    +--------------+--------------+   |
|             |                             |                  |
+-------------|-----------------------------|------------------+
              |                             |
      AES-256-GCM Encryption                |
              |                             |
              v                             v
+-----------------------------+   +----------------------------+
|     Supabase PostgreSQL     |   |    Cron-Job / UptimeRobot  |
|  - wa_auth_vault (Encrypted)|   |    Pings /api/health 5min  |
|  - wa_recent_messages       |   |    Keeps Container 24/7    |
+-----------------------------+   +----------------------------+
```

---

## Prerequisites

1. **Node.js**: v18.0.0 or higher.
2. **Supabase Account (Free Tier)**: For storing the encrypted auth vault.
3. **Cloud Host (Render / Koyeb / Railway / VPS)**: Free tier web service.
4. **Cron Pinger (cron-job.org or UptimeRobot)**: Free ping service to keep the container awake.

---

## Step 1: Database Setup (Supabase)

1. Open your [Supabase Dashboard](https://supabase.com) and create a new project.
2. Navigate to **SQL Editor** in the left sidebar.
3. Paste and execute the contents of `supabase/schema.sql`:
   - Creates `wa_auth_vault` (primary key `id`, encrypted payload, automatic timestamps).
   - Creates `wa_recent_messages` (persists recent message summaries with auto-pruning trigger).
4. Navigate to **Project Settings** -> **API**:
   - Copy **Project URL** (`SUPABASE_URL`).
   - Copy the **service_role** secret key (`SUPABASE_KEY`).

---

## Step 2: Environment Configuration

Create a `.env` file in the project root:

```bash
cp .env.example .env
```

Generate your 32-byte (256-bit) encryption key using Node:
```bash
node -e "console.log(require('crypto').randomBytes(32).toString('hex'))"
```

Fill in `.env`:
```env
PORT=3000
NODE_ENV=production

# Supabase Credentials
SUPABASE_URL=https://your-project.supabase.co
SUPABASE_KEY=your_service_role_secret_key

# 32-Byte Hex Encryption Key (64 hex characters)
VAULT_SECRET_KEY=e83b4f6a1c890d2e5a7b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f

# Web Control Center Access PIN
ADMIN_PIN=4928

# JWT Signing Secret
JWT_SECRET=super_secret_session_guard_token_seed_string_987654321

# Session ID
SESSION_ID=main_session
```

---

## Step 3: Local Installation & Development

```bash
# Install dependencies
npm install

# Compile TypeScript
npm run build

# Start server in production mode
npm start

# Or run live reload in development
npm run dev
```

Open your browser at `http://localhost:3000`:
1. Enter your `ADMIN_PIN` to unlock the dashboard.
2. Choose your preferred linking mode:
   - **Instant QR Code:** Scan directly from your phone.
   - **8-Character Pairing Code:** Enter your phone number with country code (e.g., `14155552671`) and enter the 8-character code in WhatsApp (`Linked Devices` -> `Link with phone number instead`).
3. Once linked, the status badge turns **Connected 24/7**.
4. Test the link using the **Send Test Ping to Myself** button.

---

## Step 4: Free 24/7 Cloud Deployment (Render.com)

1. Push this repository to GitHub or GitLab.
2. Log in to [Render.com](https://render.com) and click **New +** -> **Blueprint**.
3. Select your repository. Render automatically reads `render.yaml`.
4. Fill in the environment variables:
   - `SUPABASE_URL`
   - `SUPABASE_KEY`
   - `ADMIN_PIN`
5. Click **Apply**. Render will build and deploy the application.

### Setting up the Anti-Sleep Cron Pinger (100% Free)
Render free services spin down after 15 minutes of inactivity. To keep your gateway alive 24/7:
1. Go to [cron-job.org](https://cron-job.org) (free account).
2. Create a new Cronjob:
   - **Title:** `WAKeep Keep-Alive`
   - **URL:** `https://your-service-name.onrender.com/api/health`
   - **Schedule:** Every 5 minutes (`*/5 * * * *`).
3. Click **Create**.
4. Your service will now remain awake 24/7 without incurring charges.

---

## REST API Reference

| Endpoint | Method | Auth | Description |
|---|---|---|---|
| `/api/health` | `GET` | Public | Keep-alive telemetry for uptime pingers |
| `/api/auth/login` | `POST` | Public (Rate-limited) | Validates `ADMIN_PIN` and returns 7-day JWT token |
| `/api/auth/verify` | `GET` | Token | Checks current login session validity |
| `/api/auth/logout` | `POST` | Public | Clears authentication cookie |
| `/api/session/status` | `GET` | PIN Auth | Telemetry (uptime, heap RAM, connection state, user) |
| `/api/session/pair` | `POST` | PIN Auth | Generates an 8-character pairing code for a phone number |
| `/api/session/message` | `POST` | PIN Auth | Sends a message to a recipient phone number or JID |
| `/api/session/ping` | `POST` | PIN Auth | Dispatches a self-addressed test ping to verified phone |
| `/api/session/reset` | `POST` | PIN Auth | Wipes Supabase vault and initiates a fresh QR handshake |
| `/api/session/messages` | `GET` | PIN Auth | Retrieves recent 50 messages from Supabase cache |

---

## Security Best Practices

1. **Always Use Service Role Key for Backend:** Never expose your Supabase Service Role key in public client bundles. It is used strictly on the server to authenticate database queries.
2. **Key Rotation:** If you change your `VAULT_SECRET_KEY`, use the dashboard's **Reset Vault** button to wipe old credentials and link afresh with the new encryption key.
3. **Rate Limiting:** The login route is protected with `express-rate-limit` (15 attempts per 15 minutes) to protect against PIN brute-force attempts.
4. **Helmet Headers:** Hardened with security response headers across all HTTP endpoints.

---

## License
MIT License. Created for personal, educational, and persistent automation projects.
