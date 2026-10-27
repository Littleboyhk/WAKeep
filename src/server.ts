import cookieParser from 'cookie-parser';
import cors from 'cors';
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
import { WhatsAppClientManager } from './services/whatsappClient.js';

dotenv.config();

const app = express();
const server = http.createServer(app);
const io = new SocketIOServer(server, {
  cors: {
    origin: '*',
    methods: ['GET', 'POST']
  }
});

const PORT = parseInt(process.env.PORT || '3000', 10);
const ADMIN_PIN = process.env.ADMIN_PIN || '4928';
const JWT_SECRET = process.env.JWT_SECRET || 'wakeep_secure_default_secret_seed';
const VAULT_SECRET_KEY = process.env.VAULT_SECRET_KEY || 'e83b4f6a1c890d2e5a7b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f';
const SUPABASE_URL = process.env.SUPABASE_URL || '';
const SUPABASE_KEY = process.env.SUPABASE_KEY || '';
const SESSION_ID = process.env.SESSION_ID || 'main_session';

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

// Instantiate WhatsApp Client Manager
const waManager = new WhatsAppClientManager({
  supabase,
  vaultSecret: VAULT_SECRET_KEY,
  sessionId: SESSION_ID,
  io
});

// Configure Middleware
app.use(helmet({ contentSecurityPolicy: false }));
app.use(cors({ origin: true, credentials: true }));
app.use(express.json());
app.use(cookieParser());

// Rate Limiting for Authentication Route to prevent brute force
const loginRateLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 15, // Limit to 15 attempts
  message: { error: 'Too many authentication attempts. Please try again after 15 minutes.' },
  standardHeaders: true,
  legacyHeaders: false
});

/**
 * Authentication Middleware: Validates JWT token from Bearer header or cookie
 */
interface AuthenticatedRequest extends Request {
  userRole?: string;
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
    res.status(401).json({ error: 'Unauthorized: PIN authentication required.' });
    return;
  }

  try {
    const decoded = jwt.verify(token, JWT_SECRET) as { role: string };
    req.userRole = decoded.role;
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
    uptime: Math.floor(process.uptime()),
    timestamp: Date.now(),
    heapUsedMB: Math.round((memory.heapUsed / 1024 / 1024) * 10) / 10
  });
});

// ----------------------------------------------------------------------------
// Authentication Endpoints
// ----------------------------------------------------------------------------
app.post('/api/auth/login', loginRateLimiter, (req: Request, res: Response) => {
  const { pin } = req.body;

  if (!pin || String(pin).trim() !== String(ADMIN_PIN).trim()) {
    res.status(401).json({ error: 'Invalid PIN. Access denied.' });
    return;
  }

  // Issue 7-day JWT token
  const token = jwt.sign({ role: 'admin' }, JWT_SECRET, { expiresIn: '7d' });

  res.cookie('wakeep_token', token, {
    httpOnly: true,
    secure: process.env.NODE_ENV === 'production',
    sameSite: 'lax',
    maxAge: 7 * 24 * 60 * 60 * 1000 // 7 days
  });

  res.json({
    success: true,
    token,
    message: 'Authentication successful.'
  });
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
    jwt.verify(token, JWT_SECRET);
    res.json({ authenticated: true });
  } catch {
    res.json({ authenticated: false });
  }
});

app.post('/api/auth/logout', (_req: Request, res: Response) => {
  res.clearCookie('wakeep_token');
  res.json({ success: true, message: 'Logged out.' });
});

// ----------------------------------------------------------------------------
// Protected Session Management Endpoints
// ----------------------------------------------------------------------------
app.get('/api/session/status', requirePinAuth, (_req: Request, res: Response) => {
  const telemetry = waManager.getTelemetry();
  res.json({
    ...telemetry,
    qrDataUrl: waManager.getQrCode(),
    pairingCode: waManager.getLastPairingCode(),
    vaultConnected: Boolean(SUPABASE_URL && SUPABASE_KEY)
  });
});

app.post('/api/session/pair', requirePinAuth, async (req: Request, res: Response) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) {
    res.status(400).json({ error: 'Phone number is required.' });
    return;
  }

  try {
    const code = await waManager.requestPairingCode(phoneNumber);
    res.json({ success: true, code });
  } catch (err: any) {
    res.status(400).json({ error: err.message || 'Failed to request pairing code.' });
  }
});

app.post('/api/session/message', requirePinAuth, async (req: Request, res: Response) => {
  const { recipient, text } = req.body;
  if (!recipient || !text) {
    res.status(400).json({ error: 'Recipient and text are both required.' });
    return;
  }

  try {
    const result = await waManager.sendMessage(recipient, text);
    res.json({ success: true, result });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to send message.' });
  }
});

app.post('/api/session/ping', requirePinAuth, async (_req: Request, res: Response) => {
  try {
    const result = await waManager.sendTestPingToSelf();
    res.json({ success: true, result, message: 'Test ping dispatched to connected phone.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to send test ping.' });
  }
});

app.post('/api/session/reset', requirePinAuth, async (_req: Request, res: Response) => {
  try {
    await waManager.resetVault();
    res.json({ success: true, message: 'Vault cleared and fresh session initialized.' });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to reset vault.' });
  }
});

app.get('/api/session/messages', requirePinAuth, async (_req: Request, res: Response) => {
  try {
    const { data, error } = await supabase
      .from('wa_recent_messages')
      .select('*')
      .order('message_timestamp', { ascending: false })
      .limit(50);

    if (error) {
      res.status(500).json({ error: error.message });
      return;
    }

    res.json({ messages: data || [] });
  } catch (err: any) {
    res.status(500).json({ error: err.message || 'Failed to fetch messages.' });
  }
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
// Socket.IO Bridge Handshake & Connection Handling
// ----------------------------------------------------------------------------
io.use((socket, next) => {
  const token = socket.handshake.auth?.token || socket.handshake.headers?.cookie?.match(/wakeep_token=([^;]+)/)?.[1];
  if (!token) {
    // Allow initial connection for login screen, but client will request auth validation
    return next();
  }
  try {
    jwt.verify(token, JWT_SECRET);
    (socket as any).authenticated = true;
    next();
  } catch {
    next();
  }
});

io.on('connection', (socket) => {
  // Send current telemetry state on connect
  const telemetry = waManager.getTelemetry();
  socket.emit('session_status', {
    ...telemetry,
    qrDataUrl: waManager.getQrCode(),
    pairingCode: waManager.getLastPairingCode()
  });

  socket.on('request_status', () => {
    socket.emit('session_status', {
      ...waManager.getTelemetry(),
      qrDataUrl: waManager.getQrCode(),
      pairingCode: waManager.getLastPairingCode()
    });
  });
});

// ----------------------------------------------------------------------------
// Server Startup and Initialization
// ----------------------------------------------------------------------------
server.listen(PORT, async () => {
  console.log(`=======================================================`);
  console.log(`🚀 WAKeep started on port ${PORT}`);
  console.log(`📡 Health Check URL: http://localhost:${PORT}/api/health`);
  console.log(`🔒 Vault ID: ${SESSION_ID}`);
  console.log(`=======================================================`);

  // Start WhatsApp Client if Supabase credentials are configured
  if (SUPABASE_URL && SUPABASE_KEY && !SUPABASE_URL.includes('placeholder')) {
    console.log('[Server] Initializing WhatsApp Client with Supabase Vault...');
    waManager.init().catch((err) => {
      console.error('[Server] Initial WhatsApp connection failed:', err);
    });
  } else {
    console.warn('[Server] Supabase credentials not set or placeholder detected in .env.');
    console.warn('[Server] Please configure SUPABASE_URL and SUPABASE_KEY to start WhatsApp Gateway.');
  }
});

// Graceful Shutdown Handling
const handleTermination = async (signal: string) => {
  console.log(`[Server] Received ${signal}. Starting graceful shutdown...`);
  await waManager.shutdown();
  server.close(() => {
    console.log('[Server] HTTP server closed cleanly.');
    process.exit(0);
  });
};

process.on('SIGINT', () => handleTermination('SIGINT'));
process.on('SIGTERM', () => handleTermination('SIGTERM'));

export { app, server, waManager };
