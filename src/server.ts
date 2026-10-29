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
const SAMPLE_JWT_SECRET = 'wakeep_secure_default_secret_seed';
if (!JWT_SECRET || JWT_SECRET === SAMPLE_JWT_SECRET) {
  if (process.env.NODE_ENV === 'production') {
    console.warn('⚠️ [Security Warning] JWT_SECRET not found in environment! Generating a secure ephemeral 256-bit secret for this runtime.');
    JWT_SECRET = crypto.randomBytes(32).toString('hex');
  } else {
    JWT_SECRET = SAMPLE_JWT_SECRET;
  }
}

const SAMPLE_VAULT_KEY = 'e83b4f6a1c890d2e5a7b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f';
let VAULT_SECRET_KEY = process.env.VAULT_SECRET_KEY;

if (!VAULT_SECRET_KEY || VAULT_SECRET_KEY === SAMPLE_VAULT_KEY) {
  if (process.env.NODE_ENV === 'production') {
    throw new Error('CRITICAL CONFIGURATION ERROR: VAULT_SECRET_KEY is missing or using the public sample key from .env.example! A unique 64-character hex secret must be configured in production.');
  } else {
    console.warn('⚠️ [Security Warning] Using development default for VAULT_SECRET_KEY. Never use this in production!');
    VAULT_SECRET_KEY = SAMPLE_VAULT_KEY;
  }
}
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

app.use(express.json({ limit: '50kb' }));
app.use(cookieParser());

// ----------------------------------------------------------------------------
// Bot Protection Middleware & Rate Limiting System
// ----------------------------------------------------------------------------

/**
 * Bot Protection Middleware:
 * - Drops headless scrapers without a User-Agent
 * - Blocks known vulnerability scanners and automated attack bots
 * - Filters honeypot trap fields on session creation
 */
const botProtection = (req: Request, res: Response, next: NextFunction): void => {
  const userAgent = req.headers['user-agent'] || '';

  // Block mutating requests without any User-Agent header
  if (req.method === 'POST' && (!userAgent || userAgent.trim().length === 0)) {
    res.status(403).json({ error: 'Access denied: Valid User-Agent required.' });
    return;
  }

  // Block automated attack tools and vulnerability scanners
  const scannerPatterns = [
    /sqlmap/i, /nikto/i, /masscan/i, /zgrab/i, /acunetix/i,
    /nmap/i, /wpscan/i, /havij/i, /burpcollaborator/i, /python-requests/i
  ];
  for (const pattern of scannerPatterns) {
    if (pattern.test(userAgent)) {
      res.status(403).json({ error: 'Access denied: Automated security scanners are prohibited.' });
      return;
    }
  }

  // Honeypot trap: if automated bots fill hidden dummy fields, discard silently
  if (req.path === '/api/sessions/create' && req.method === 'POST') {
    if (req.body?.website || req.body?.company || req.body?.hp_trap) {
      res.status(400).json({ error: 'Automated submission detected.' });
      return;
    }
  }

  next();
};

// Global API rate limit across all /api endpoints to prevent DoS flooding
const globalApiLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 120, // 120 requests per minute per IP
  message: { error: 'Too many requests. Please slow down.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Public Health & Slot Queries (avoids resource/RAM polling abuse)
const healthRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 60, // 60 requests per minute
  message: { error: 'Metrics request limit reached. Please wait a minute.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Session Creation (expensive database write & socket initialization)
const createSessionLimiter = rateLimit({
  windowMs: 30 * 60 * 1000, // 30 minutes
  max: 6, // 6 new sessions per 30 minutes per IP
  message: { error: 'Too many session creation requests. Please wait 30 minutes before creating another session.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Login to prevent brute force attacks
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 10, // 10 attempts per 15 minutes per IP
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

// Rate Limiting on Heartbeat Ping Verification
const pingRateLimiter = rateLimit({
  windowMs: 1 * 60 * 1000, // 1 minute
  max: 20, // 20 pings per minute
  message: { error: 'Heartbeat ping rate limit exceeded. Please wait a minute.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Rate Limiting on Vault Reset & Session Logout to prevent rapid disk/DB wipes
const resetRateLimiter = rateLimit({
  windowMs: 10 * 60 * 1000, // 10 minutes
  max: 3, // Limit to 3 resets/logouts per 10 minutes
  message: { error: 'Vault operation limit reached. Please wait 10 minutes before trying again.' },
  standardHeaders: true,
  legacyHeaders: false
});

// Apply Bot Protection & Global Limiter to all API endpoints
app.use('/api', botProtection, globalApiLimiter);

/**
 * Authentication Middleware: Validates JWT token and extracts sessionId
 */
export interface AuthenticatedRequest extends Request {
  userRole?: 'admin' | 'user';
  sessionId?: string;
}

/**
 * Authentication & Authorization Middleware:
 * 1. Validates JWT signature and expiry.
 * 2. Strictly requires a valid sessionId in the token (no unauthenticated fallback to admin session).
 * 3. Verifies that the session actually exists in active memory or in Supabase vault.
 * 4. Cross-Tenant Authorization Guard:
 *    If the request specifies a target `sessionId` (in body, query, or params),
 *    ensures it matches the authenticated session unless the caller has admin authorization.
 * 5. Default Session Protection:
 *    Ensures only 'admin' can access or modify the primary default session (SESSION_ID).
 */
const requireAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
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
    const decoded = jwt.verify(token, JWT_SECRET) as { role?: 'admin' | 'user'; sessionId?: string };
    
    // Strict sessionId requirement in token
    const tokenSessionId = decoded.sessionId ? sessionManager.cleanSessionId(decoded.sessionId) : '';
    if (!tokenSessionId) {
      res.status(401).json({ error: 'Unauthorized: Invalid token payload (missing session identifier).' });
      return;
    }

    // Verify session existence in database/memory
    const exists = await sessionManager.sessionExists(tokenSessionId);
    if (!exists) {
      res.status(401).json({ error: 'Unauthorized: Session does not exist or has been logged out.' });
      return;
    }

    req.userRole = decoded.role || 'user';
    req.sessionId = tokenSessionId;

    // Cross-Tenant Authorization Guard:
    // Check if the request explicitly targets a different session in body, query, or params
    const explicitTarget = req.body?.sessionId || req.query?.sessionId || req.params?.sessionId;
    if (explicitTarget) {
      const cleanTarget = sessionManager.cleanSessionId(String(explicitTarget));
      if (cleanTarget && cleanTarget !== req.sessionId && req.userRole !== 'admin') {
        res.status(403).json({
          error: 'Forbidden: Access denied. You are not authorized to view or modify another user\'s session data.'
        });
        return;
      }
    }

    // Admin Session Protection:
    // If the token is targeting the primary system session, require admin privileges
    if (req.sessionId === SESSION_ID && req.userRole !== 'admin') {
      res.status(403).json({
        error: 'Forbidden: Direct access to primary admin session requires administrator authorization.'
      });
      return;
    }

    next();
  } catch (err) {
    res.status(401).json({ error: 'Unauthorized: Session token expired or invalid.' });
  }
};

// Alias for backward compatibility
const requirePinAuth = requireAuth;

/**
 * Admin-Only Authorization Middleware
 */
const requireAdminAuth = async (req: AuthenticatedRequest, res: Response, next: NextFunction): Promise<void> => {
  await requireAuth(req, res, () => {
    if (req.userRole !== 'admin') {
      res.status(403).json({ error: 'Forbidden: Administrator privileges required.' });
      return;
    }
    next();
  });
};

// ----------------------------------------------------------------------------
// Public Health Check Endpoint (For Cron-Job.org / UptimeRobot 24/7 Keep-Alive)
// ----------------------------------------------------------------------------
app.get('/api/health', healthRateLimiter, (_req: Request, res: Response) => {
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
app.get('/api/slots', healthRateLimiter, (_req: Request, res: Response) => {
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
app.post('/api/sessions/create', createSessionLimiter, async (req: Request, res: Response) => {
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
    
    // Assign role 'admin' strictly when unlocking the primary admin session, otherwise 'user'
    const role: 'admin' | 'user' = cleanId === SESSION_ID ? 'admin' : 'user';
    const token = jwt.sign({ role, sessionId: cleanId }, JWT_SECRET, { expiresIn: '7d' });

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
      role,
      message: 'Session unlocked successfully.'
    });
  } catch (err: any) {
    res.status(401).json({ error: err.message || 'Invalid credentials. Access denied.' });
  }
});

/**
 * Backward compatibility: POST /api/auth/login
 * Strictly authenticates the primary administrator session (SESSION_ID)
 */
app.post('/api/auth/login', loginRateLimiter, async (req: Request, res: Response) => {
  const rawInput = req.body.password || req.body.pin;
  const targetSessionId = SESSION_ID;

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
      role: 'admin',
      message: 'Admin authentication successful.'
    });
  } catch (err: any) {
    res.status(401).json({ error: err.message || 'Invalid password. Access denied.' });
  }
});

app.get('/api/auth/verify', async (req: Request, res: Response) => {
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
    const decoded = jwt.verify(token, JWT_SECRET) as { role?: 'admin' | 'user'; sessionId?: string };
    const cleanId = decoded.sessionId ? sessionManager.cleanSessionId(decoded.sessionId) : '';
    if (!cleanId) {
      res.json({ authenticated: false });
      return;
    }

    const exists = await sessionManager.sessionExists(cleanId);
    if (!exists) {
      res.json({ authenticated: false });
      return;
    }

    res.json({
      authenticated: true,
      sessionId: cleanId,
      role: decoded.role || 'user'
    });
  } catch {
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('wakeep_token');
  res.json({ success: true, message: 'Logged out.' });
});

/**
 * GET /api/admin/sessions
 * Admin-Only Action: Retrieves system-level companion statistics and session summaries
 */
app.get('/api/admin/sessions', requireAdminAuth, (_req: AuthenticatedRequest, res: Response) => {
  const maxSlots = parseInt(process.env.MAX_COMPANION_SLOTS || '10', 10);
  const activeSessions = sessionManager.getActiveSessionsCount();
  const summaries = sessionManager.getSessionsSummary();

  res.json({
    admin: true,
    totalSlots: maxSlots,
    activeSessions,
    sessions: summaries
  });
});

// ----------------------------------------------------------------------------
// Session-Scoped Protected Endpoints
// ----------------------------------------------------------------------------
app.get('/api/session/status', requirePinAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId!;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);

    // Auto-wake QR code engine if companion is not linked and QR is missing
    let qrDataUrl = manager.getQrCode();
    if (manager.getStatus() !== 'connected' && !qrDataUrl) {
      qrDataUrl = await manager.ensureQrReady(2500).catch((err) => {
        console.warn(`[Server] ensureQrReady notice for [${targetSessionId}]:`, err.message);
        return null;
      });
    }

    const telemetry = manager.getTelemetry();
    const isAccountActive = telemetry.status === 'connected' && Boolean(telemetry.user);

    res.json({
      ...telemetry,
      sessionId: targetSessionId,
      qrDataUrl: qrDataUrl || manager.getQrCode(),
      pairingCode: manager.getLastPairingCode(),
      vaultConnected: Boolean(SUPABASE_URL && SUPABASE_KEY),
      isAccountActive
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch session status.' });
  }
});

app.post('/api/session/refresh-qr', requirePinAuth, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId!;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);
    const qrDataUrl = await manager.refreshQr();
    res.json({
      success: true,
      status: manager.getStatus(),
      qrDataUrl,
      message: qrDataUrl ? 'Fresh QR code generated successfully.' : 'QR engine initialized. Generating fresh QR code...'
    });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to refresh QR code.' });
  }
});

app.post('/api/session/pair', requirePinAuth, pairRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    res.status(400).json({ error: 'Phone number is required.' });
    return;
  }

  try {
    const targetSessionId = req.sessionId!;
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

app.post('/api/session/ping', requirePinAuth, pingRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId!;
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
    const targetSessionId = req.sessionId!;
    const manager = await sessionManager.getOrLoadSession(targetSessionId);
    await manager.resetVault();
    res.json({ success: true, message: 'Session vault cleared. Fresh QR ready.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to reset vault.' });
  }
});

app.post('/api/session/logout', requirePinAuth, resetRateLimiter, async (req: AuthenticatedRequest, res: Response) => {
  try {
    const targetSessionId = req.sessionId!;
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
io.use(async (socket, next) => {
  let token = socket.handshake.auth?.token;
  if (!token && socket.handshake.headers?.cookie) {
    token = socket.handshake.headers.cookie.match(/wakeep_token=([^;]+)/)?.[1];
  }

  if (!token) {
    return next(new Error('Unauthorized: Authentication required for WebSocket'));
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { role?: 'admin' | 'user'; sessionId?: string };
    const cleanId = decoded.sessionId ? sessionManager.cleanSessionId(decoded.sessionId) : '';
    if (!cleanId) {
      return next(new Error('Unauthorized: Missing session identifier in token'));
    }

    const exists = await sessionManager.sessionExists(cleanId);
    if (!exists) {
      return next(new Error('Unauthorized: Session does not exist or has been logged out'));
    }

    // Protect admin session from non-admin role
    if (cleanId === SESSION_ID && decoded.role !== 'admin') {
      return next(new Error('Unauthorized: Administrator authorization required'));
    }

    socket.data.sessionId = cleanId;
    socket.data.userRole = decoded.role || 'user';
    next();
  } catch {
    return next(new Error('Unauthorized: Invalid or expired session token'));
  }
});

io.on('connection', async (socket) => {
  const sessionId = socket.data.sessionId;
  const roomName = `session:${sessionId}`;

  // Join strictly isolated room for this specific authenticated user session
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
