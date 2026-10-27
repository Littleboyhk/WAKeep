import cookieParser from 'cookie-parser';
import cors from 'cors';
import crypto from 'crypto';
import dotenv from 'dotenv';
import express, { NextFunction, Request, Response } from 'express';
import rateLimit from 'express-rate-limit';
import helmet from 'helmet';
import http from 'http';
import jwt from 'jsonwebtoken';
import path from 'path';
import { fileURLToPath } from 'url';
import { Server as SocketIOServer } from 'socket.io';
import { createClient } from '@supabase/supabase-js';
import { MultiSessionManager } from './services/sessionManager.js';

dotenv.config();

const app = express();
const server = http.createServer(app);

// ----------------------------------------------------------------------------
// Cloud Reverse Proxy Trust (Render / Cloudflare)
// ----------------------------------------------------------------------------
// Enables accurate client IP detection for rate-limiters behind reverse proxies
app.set('trust proxy', 1);

// ----------------------------------------------------------------------------
// Environment & Secret Hardening
// ----------------------------------------------------------------------------
const PORT = parseInt(process.env.PORT || '3000', 10);

// Mandatory 8-character minimum admin password (supports ADMIN_PASSWORD or legacy ADMIN_PIN)
let ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || process.env.ADMIN_PIN;
if (!ADMIN_PASSWORD) {
  if (process.env.NODE_ENV === 'production') {
    console.warn('⚠️ [Security Alert] No ADMIN_PASSWORD set in production! Generating a cryptographically random fallback secret.');
    ADMIN_PASSWORD = crypto.randomBytes(16).toString('hex');
  } else {
    ADMIN_PASSWORD = 'wakeep#2026';
  }
}

if (ADMIN_PASSWORD.length < 8) {
  console.warn(`⚠️ [Security Alert] Configured ADMIN_PASSWORD is too short (${ADMIN_PASSWORD.length} chars). Mandatory minimum is 8 characters!`);
}

// Prevent insecure public fallback secrets in production environments
let JWT_SECRET = process.env.JWT_SECRET;
if (!JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.warn('⚠️ [Security Warning] JWT_SECRET not found in environment! Generating a secure ephemeral 256-bit secret for this runtime.');
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
  } else {
    JWT_SECRET = 'wakeep_secure_default_secret_seed';
  }
}

const VAULT_SECRET_KEY = process.env.VAULT_SECRET_KEY || 'e83b4f6a1c890d2e5a7b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const SESSION_ID = process.env.SESSION_ID || 'main_session';

// ----------------------------------------------------------------------------
// Restricted WebSocket Server (Authenticated Room Isolation)
// ----------------------------------------------------------------------------
const io = new SocketIOServer(server, {
  cors: {
    origin: false // Restrict to same-origin to prevent Cross-Site WebSocket Hijacking (CSWSH)
  }
});

// Initialize Supabase Client
const supabase = createClient(
  SUPABASE_URL || 'https://placeholder.supabase.co',
  SUPABASE_KEY || 'placeholder-key',
  {
    auth: {
      persistSession: false,
      autoRefreshToken: false
    }
  }
);

// Instantiate Multi-Session Manager
const sessionManager = new MultiSessionManager({
  supabase,
  vaultSecret: VAULT_SECRET_KEY,
  io,
  adminPassword: ADMIN_PASSWORD,
  defaultSessionId: SESSION_ID
});

// ----------------------------------------------------------------------------
// Middleware & Hardened Security Headers
// ----------------------------------------------------------------------------
app.use(helmet({
  contentSecurityPolicy: false, // Allows inline styles/scripts for CDN assets
  crossOriginEmbedderPolicy: false,
  frameguard: { action: 'sameorigin' } // Prevents Clickjacking
}));

// Restrict CORS to same-origin to prevent unauthorized cross-origin credential use
app.use(cors({
  origin: (origin, callback) => {
    // Allow server-to-server, cURL, uptime monitors, or same-origin
    if (!origin) return callback(null, true);
    return callback(null, false);
  },
  credentials: true
}));

app.use(express.json({ limit: '100kb' }));
app.use(cookieParser());

// Rate Limiting on Login / Session creation to prevent brute force attacks
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Limit each IP to 15 attempts per window
  skipSuccessfulRequests: true, // Do not penalize successful authentications
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Pairing Requests to prevent WhatsApp cooldown locks
const pairRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 5, // Limit to 5 pairing attempts per 10 minutes
  message: { error: 'Too many pairing code attempts. Please wait 10 minutes before requesting again.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Message Sending to prevent socket flooding
const messageRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 45, // Limit to 45 outgoing messages per minute
  message: { error: 'Rate limit exceeded: Please wait before sending more messages.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Vault Reset to prevent accidental or malicious rapid wipes
const resetRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 3, // Limit to 3 resets per 10 minutes
  message: { error: 'Vault reset limit reached. Please wait 10 minutes before trying again.' },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Authentication Middleware: Validates JWT token and extracts sessionId
 */
export interface AuthenticatedRequest extends Request {
  userRole?: string;
  sessionId?: string;
}

const requirePinAuth = (req: AuthenticatedRequest, res: Response, next: NextFunction): void => {
  let token = req.cookies?.wakeep_token;

  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  if (!token) {
    res.status(401).json({ error: 'Unauthorized: Session authentication required.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { role: string; sessionId?: string };
    req.userRole = decoded.role;
    req.sessionId = decoded.sessionId || SESSION_ID;
    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized: Session token expired or invalid.' });
  }
};

// ----------------------------------------------------------------------------
// Public Health Check Endpoint (For Cron-Job.org / UptimeRobot 24/7 Keep-Alive)
// ----------------------------------------------------------------------------
app.get('/api/health', (_req: Request, res: Response) => {
  const memory = process.memoryUsage();
  res.status(200).json({
    status: 'ok',
    activeSessions: sessionManager.getActiveSessionsCount(),
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now(),
    heapUsedMB: Math.round((memory.heapUsed / 1024 / 1024) * 10) / 10
  });
});

// ----------------------------------------------------------------------------
// Multi-Session Hub Endpoints (Capacity Slots, Create New Session & Login)
// ----------------------------------------------------------------------------

/**
 * GET /api/slots
 * Returns real server capacity and currently available companion slots based on active sessions
 */
app.get('/api/slots', (_req: Request, res: Response) => {
  const maxSlots = parseInt(process.env.MAX_COMPANION_SLOTS || '10', 10);
  const activeSessions = sessionManager.getActiveSessionsCount();
  const slotsRemaining = Math.max(0, maxSlots - activeSessions);
  res.setHeader('Cache-Control', 'public, max-age=5, stale-while-revalidate=15');
  res.json({
    totalSlots: maxSlots,
    activeSessions,
    slotsRemaining,
    isFull: slotsRemaining <= 0
  });
});

/**
 * POST /api/sessions/create
 * Allows any new user to create their own session and get a fresh, dedicated QR code
 */
app.post('/api/sessions/create', loginRateLimiter, async (req: Request, res: Response) => {
  const { sessionId, password, disclaimerAccepted } = req.body;

  if (!disclaimerAccepted) {
    res.status(400).json({ error: 'You must review and agree to the Disclaimer & Terms of Service before generating a QR code.' });
    return;
  }

  const maxSlots = parseInt(process.env.MAX_COMPANION_SLOTS || '10', 10);
  const activeSessions = sessionManager.getActiveSessionsCount();
  if (activeSessions >= maxSlots) {
    res.status(503).json({
      error: `All ${maxSlots} companion slots on this server are currently occupied (${activeSessions}/${maxSlots} active). Please wait for a slot to free up or deploy your own free private instance using GitHub.`
    });
    return;
  }

  if (!sessionId || !password) {
    res.status(400).json({ error: 'Session Name and Password (minimum 8 characters) are required.' });
    return;
  }

  try {
    const { manager, sessionId: cleanId } = await sessionManager.createSession(sessionId, password);
    const token = jwt.sign({ role: 'user', sessionId: cleanId }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('wakeep_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      token,
      sessionId: cleanId,
      message: 'New session created successfully. Ready for QR scan.'
    });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to create new session.' });
  }
});

/**
 * POST /api/sessions/login
 * Allows returning users to unlock their private session console
 */
app.post('/api/sessions/login', loginRateLimiter, async (req: Request, res: Response) => {
  const { sessionId, password } = req.body;
  const targetSessionId = sessionId || req.body.pin ? (sessionId || SESSION_ID) : SESSION_ID;
  const pass = password || req.body.pin;

  if (!pass) {
    res.status(400).json({ error: 'Password is required.' });
    return;
  }

  try {
    const { manager, sessionId: cleanId } = await sessionManager.loginSession(targetSessionId, pass);
    const token = jwt.sign({ role: 'user', sessionId: cleanId }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('wakeep_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      token,
      sessionId: cleanId,
      message: 'Session unlocked successfully.'
    });
  } catch (err: any) {
    res.status(401).json({ error: err.message || 'Invalid credentials. Access denied.' });
  }
});

/**
 * Backward compatibility: POST /api/auth/login
 */
app.post('/api/auth/login', loginRateLimiter, async (req: Request, res: Response) => {
  const rawInput = req.body.password || req.body.pin;
  const targetSessionId = req.body.sessionId || SESSION_ID;

  if (!rawInput) {
    res.status(400).json({ error: 'Password is required.' });
    return;
  }

  try {
    const { manager, sessionId: cleanId } = await sessionManager.loginSession(targetSessionId, rawInput);
    const token = jwt.sign({ role: 'admin', sessionId: cleanId }, JWT_SECRET, { expiresIn: '7d' });

    res.cookie('wakeep_token', token, {
      httpOnly: true,
      secure: process.env.NODE_ENV === 'production',
      sameSite: 'lax',
      maxAge: 7 * 24 * 60 * 60 * 1000
    });

    res.json({
      success: true,
      token,
      sessionId: cleanId,
      message: 'Authentication successful.'
    });
  } catch (err: any) {
    res.status(401).json({ error: err.message || 'Invalid password. Access denied.' });
  }
});

app.get('/api/auth/verify', (req: Request, res: Response) => {
  let token = req.cookies?.wakeep_token;
  if (!token && req.headers.authorization) {
    const parts = req.headers.authorization.split(' ');
    if (parts.length === 2 && parts[0] === 'Bearer') {
      token = parts[1];
    }
  }

  if (!token) {
    res.json({ authenticated: false });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { sessionId?: string };
    res.json({ authenticated: true, sessionId: decoded.sessionId || SESSION_ID });
  } catch {
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('wakeep_token');
  res.json({ success: true, message: 'Logged out.' });
});

// ----------------------------------------------------------------------------
// Session-Scoped Protected Endpoints
// ----------------------------------------------------------------------------
app.get('/api/session/status', requirePinAuth, async (req: AuthenticatedRequest, res: Response) => {
  const targetSessionId = req.sessionId || SESSION_ID;
  const manager = await sessionManager.getOrLoadSession(targetSessionId);
  const telemetry = manager.getTelemetry();
  const isAccountActive = telemetry.status === 'connected' && Boolean(telemetry.user);

  res.json({
    ...telemetry,
    sessionId: targetSessionId,
    qrDataUrl: manager.getQrCode(),
    pairingCode: manager.getLastPairingCode(),
    vaultConnected: Boolean(SUPABASE_URL && SUPABASE_KEY),
    isAccountActive
  });
});

app.post('/api/session/pair', requirePinAuth, pairRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    res.status(400).json({ error: 'Phone number is required.' });
    return;
  }

  try {
    const targetSessionId = req.sessionId || SESSION_ID;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);
    const code = await manager.requestPairingCode(phoneNumber);
    res.json({ success: true, code });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to request pairing code.' });
  }
});

app.post('/api/session/message', requirePinAuth, async (_req: Request, res: Response) => {
  // Privacy & Safety: Zero Messaging Capability
  res.status(403).json({
    error: 'Message sending is disabled. WAKeep is strictly a 24/7 session keep-alive service with zero message capabilities.'
  });
});

app.post('/api/session/ping', requirePinAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId || SESSION_ID;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);
    const status = manager.getStatus();
    const user = manager.getUserProfile();

    if (status !== 'connected' || !user) {
      res.status(400).json({
        success: false,
        status,
        error: 'WhatsApp companion is NOT active or linked yet. Please scan the QR code to connect your account first.'
      });
      return;
    }

    res.json({
      success: true,
      status,
      user,
      message: '24/7 Keep-alive heartbeat verified successfully.'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to verify heartbeat.' });
  }
});

app.post('/api/session/reset', requirePinAuth, resetRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId || SESSION_ID;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);
    await manager.resetVault();
    res.json({ success: true, message: 'Session vault cleared. Fresh QR ready.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to reset vault.' });
  }
});

app.post('/api/session/logout', requirePinAuth, resetRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId || SESSION_ID;
    await sessionManager.logoutAndRemoveSession(targetSessionId);
    res.json({ success: true, message: 'WhatsApp account logged out and purged from server successfully.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to logout WhatsApp account.' });
  }
});

app.get('/api/session/messages', requirePinAuth, async (_req: Request, res: Response) => {
  // Privacy Guarantee: Zero Data Collection active — No user messages are logged or collected
  res.json({
    messages: [],
    privacy: 'Zero Data Collection active. WAKeep does not record or read personal messages.'
  });
});

// ----------------------------------------------------------------------------
// Static Assets & Single Page Application Serving
// ----------------------------------------------------------------------------
const __filename = fileURLToPath(import.meta.url);
const __dirname = path.dirname(__filename);
const publicDir = path.join(__dirname, '../public');
app.use(express.static(publicDir));

app.get('*', (_req: Request, res: Response) => {
  res.sendFile(path.join(publicDir, 'index.html'));
});

// ----------------------------------------------------------------------------
// Hardened Socket.IO Authentication & Channel Isolation
// ----------------------------------------------------------------------------
io.use((socket, next) => {
  let token = socket.handshake.auth?.token;
  if (!token && socket.handshake.headers?.cookie) {
    token = socket.handshake.headers.cookie.match(/wakeep_token=([^;]+)/)?.[1];
  }

  if (!token) {
    return next(new Error('Unauthorized: Authentication required for WebSocket'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { sessionId?: string };
    socket.data.sessionId = decoded.sessionId || SESSION_ID;
    next();
  } catch {
    return next(new Error('Unauthorized: Invalid or expired session token'));
  }
});

io.on('connection', async (socket) => {
  const sessionId = socket.data.sessionId || SESSION_ID;
  const roomName = `session:${sessionId}`;

  // Join isolated room for this specific user session
  socket.join(roomName);

  try {
    const manager = await sessionManager.getOrLoadSession(sessionId);
    const telemetry = manager.getTelemetry();
    socket.emit('session_status', {
      ...telemetry,
      sessionId,
      qrDataUrl: manager.getQrCode(),
      pairingCode: manager.getLastPairingCode()
    });

    socket.on('request_status', () => {
      socket.emit('session_status', {
        ...manager.getTelemetry(),
        sessionId,
        qrDataUrl: manager.getQrCode(),
        pairingCode: manager.getLastPairingCode()
      });
    });
  } catch (err: any) {
    console.error(`[Socket] Error fetching session [${sessionId}]:`, err.message);
  }
});

// ----------------------------------------------------------------------------
// Server Startup and Initialization
// ----------------------------------------------------------------------------
server.listen(PORT, async () => {
  console.log(`=======================================================`);
  console.log(`🚀 WAKeep started on port ${PORT}`);
  console.log(`📡 Health Check URL: http://localhost:${PORT}/api/health`);
  console.log(`🛡️  Reverse Proxy Trust: Enabled (trust proxy: 1)`);
  console.log(`🌐 Multi-Session Hub: Active (Default: ${SESSION_ID})`);
  console.log(`=======================================================`);

  // Start Sessions from Supabase Vault
  if (SUPABASE_URL && SUPABASE_KEY && !SUPABASE_URL.includes('placeholder')) {
    console.log('[Server] Connecting Multi-Session Manager to Supabase Vault...');
    await sessionManager.init();
  } else {
    console.warn('[Server] Supabase credentials not set or placeholder detected in .env.');
  }
});

// Graceful Shutdown Handling
const handleTermination = async (signal: string) => {
  console.log(`[Server] Received ${signal}. Starting graceful shutdown...`);
  await sessionManager.shutdownAll();
  server.close(() => {
    console.log('[Server] HTTP server closed cleanly.');
    process.exit(0);
  });
};

process.on('SIGINT', () => handleTermination('SIGINT'));
process.on('SIGTERM', () => handleTermination('SIGTERM'));

export { app, server, sessionManager };
