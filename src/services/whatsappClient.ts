import { Boom } from '@hapi/boom';
import { SupabaseClient } from '@supabase/supabase-js';
import makeWASocket, {
  Browsers,
  ConnectionState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  proto,
  WASocket
} from '@whiskeysockets/baileys';
import pino from 'pino';
import QRCode from 'qrcode';
import { Server as SocketIOServer } from 'socket.io';
import { SupabaseAuthStateResult, useSupabaseAuthState } from '../lib/supabaseAuthState.js';

export type SessionConnectionStatus =
  | 'idle'
  | 'connecting'
  | 'waiting_qr'
  | 'pairing'
  | 'connected'
  | 'reconnecting'
  | 'logged_out'
  | 'error';

export interface WhatsAppClientOptions {
  supabase: SupabaseClient;
  vaultSecret: string;
  sessionId?: string;
  io?: SocketIOServer;
}

export interface ChatMessageSummary {
  message_id: string;
  chat_jid: string;
  sender_jid: string;
  sender_name: string;
  from_me: boolean;
  text_content: string;
  message_timestamp: number;
  created_at?: string;
}

export class WhatsAppClientManager {
  private supabase: SupabaseClient;
  private vaultSecret: string;
  private sessionId: string;
  private io?: SocketIOServer;

  private sock: WASocket | null = null;
  private authStateResult: SupabaseAuthStateResult | null = null;
  private status: SessionConnectionStatus = 'idle';
  private currentQrDataUrl: string | null = null;
  private lastPairingCode: string | null = null;
  private reconnectAttempts = 0;
  private reconnectTimer: NodeJS.Timeout | null = null;
  private isExplicitDisconnect = false;
  private startTime = Date.now();

  constructor(options: WhatsAppClientOptions) {
    this.supabase = options.supabase;
    this.vaultSecret = options.vaultSecret;
    this.sessionId = options.sessionId || 'main_session';
    this.io = options.io;
  }

  public setSocketIO(io: SocketIOServer) {
    this.io = io;
  }

  public getStatus(): SessionConnectionStatus {
    return this.status;
  }

  public getQrCode(): string | null {
    return this.currentQrDataUrl;
  }

  public getLastPairingCode(): string | null {
    return this.lastPairingCode;
  }

  public getUserProfile() {
    if (!this.sock?.user) return null;
    return {
      id: this.sock.user.id,
      name: this.sock.user.name || null,
      phone: this.sock.user.id.split('@')[0].split(':')[0]
    };
  }

  public getTelemetry() {
    const memory = process.memoryUsage();
    return {
      status: this.status,
      uptimeSeconds: Math.floor(process.uptime()),
      startedAt: this.startTime,
      user: this.getUserProfile(),
      hasQr: !!this.currentQrDataUrl,
      reconnectAttempts: this.reconnectAttempts,
      ramUsage: {
        heapUsedMB: Math.round((memory.heapUsed / 1024 / 1024) * 10) / 10,
        heapTotalMB: Math.round((memory.heapTotal / 1024 / 1024) * 10) / 10,
        rssMB: Math.round((memory.rss / 1024 / 1024) * 10) / 10
      }
    };
  }

  public getSessionId(): string {
    return this.sessionId;
  }

  private broadcastStatus() {
    if (!this.io) return;
    const telemetry = this.getTelemetry();
    this.io.to(`session:${this.sessionId}`).emit('session_status', {
      ...telemetry,
      sessionId: this.sessionId,
      qrDataUrl: this.currentQrDataUrl,
      pairingCode: this.lastPairingCode
    });
  }

  /**
   * Initializes or re-establishes the WhatsApp connection
   */
  public async init(): Promise<void> {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    this.isExplicitDisconnect = false;
    this.status = 'connecting';
    this.broadcastStatus();

    try {
      // Initialize encrypted Supabase auth state
      this.authStateResult = await useSupabaseAuthState(
        this.supabase,
        this.vaultSecret,
        this.sessionId
      );

      // Fetch the latest Baileys version dynamically for best compatibility
      const { version, isLatest } = await fetchLatestBaileysVersion().catch(() => ({
        version: [2, 3000, 1043857760] as [number, number, number],
        isLatest: true
      }));

      console.log(`[WhatsAppClient] Starting socket for [${this.sessionId}] with Baileys v${version.join('.')} (latest: ${isLatest})`);

      // Create socket with anti-disconnect, low-RAM, and desktop spoofing options
      this.sock = makeWASocket({
        version,
        auth: this.authStateResult.state,
        logger: pino({ level: 'silent' }),
        printQRInTerminal: false,
        // Official Baileys Ubuntu Chrome companion signature
        browser: Browsers.ubuntu('Chrome'),
        // Keep primary phone active without trigger notifications
        markOnlineOnConnect: false,
        // NAT keep-alive interval: 25 seconds
        keepAliveIntervalMs: 25000,
        // Minimize RAM consumption to stay under free tier 70MB limits
        syncFullHistory: false,
        generateHighQualityLinkPreview: false,
        getMessage: async () => undefined
      });

      this.registerEvents();
    } catch (err: any) {
      console.error('[WhatsAppClient] Failed to initialize socket:', err.message);
      this.status = 'error';
      this.broadcastStatus();
      this.scheduleReconnect();
    }
  }

  private registerEvents(): void {
    if (!this.sock) return;

    // Credentials update event
    this.sock.ev.on('creds.update', async () => {
      try {
        if (this.authStateResult) {
          await this.authStateResult.saveCreds();
        }
      } catch (saveErr: any) {
        console.error('[WhatsAppClient] Error auto-saving credentials:', saveErr.message);
      }
    });

    // Connection state update event
    this.sock.ev.on('connection.update', async (update: Partial<ConnectionState>) => {
      const { connection, lastDisconnect, qr } = update;

      if (qr) {
        try {
          this.currentQrDataUrl = await QRCode.toDataURL(qr, {
            margin: 2,
            width: 320,
            color: {
              dark: '#0f172a',
              light: '#ffffff'
            }
          });
          this.status = 'waiting_qr';
          this.reconnectAttempts = 0;
          console.log(`[WhatsAppClient] New QR code generated successfully for [${this.sessionId}]`);
          this.broadcastStatus();
        } catch (qrErr: any) {
          console.error('[WhatsAppClient] Error generating QR DataURL:', qrErr.message);
        }
      }

      if (connection === 'open') {
        this.status = 'connected';
        this.currentQrDataUrl = null;
        this.lastPairingCode = null;
        this.reconnectAttempts = 0;
        console.log(`[WhatsAppClient] Connected successfully as ${this.sock?.user?.id}`);
        this.broadcastStatus();
      }

      if (connection === 'close') {
        const statusCode = (lastDisconnect?.error as Boom)?.output?.statusCode ||
          (lastDisconnect?.error as any)?.statusCode;
        const reason = DisconnectReason[statusCode] || `Code ${statusCode}`;

        console.log(`[WhatsAppClient] Connection closed for [${this.sessionId}]. Reason: ${reason} (${statusCode})`);

        this.currentQrDataUrl = null;

        if (this.isExplicitDisconnect) {
          this.status = 'idle';
          this.broadcastStatus();
          return;
        }

        // When QR times out or session is unlinked/logged out (401), clean up stale creds
        // and immediately restart Baileys with fresh state so a fresh QR code is always emitted!
        const isNotConnected = this.status !== 'connected';
        if (statusCode === DisconnectReason.loggedOut || (isNotConnected && (statusCode === DisconnectReason.timedOut || statusCode === DisconnectReason.connectionClosed))) {
          console.warn(`[WhatsAppClient] Session [${this.sessionId}] unlinked or QR timed out. Resetting auth state for fresh QR...`);
          this.status = 'waiting_qr';
          this.broadcastStatus();

          if (this.authStateResult && isNotConnected) {
            this.authStateResult.clearVault().catch((clearErr: any) => {
              console.warn('[WhatsAppClient] Non-fatal vault clear notice:', clearErr.message);
            });
          }

          // Restart cleanly in 1.0 second to regenerate fresh QR code immediately
          this.scheduleReconnect(1000);
          return;
        }

        this.status = 'reconnecting';
        this.broadcastStatus();
        this.scheduleReconnect();
      }
    });
  }

  private scheduleReconnect(delayMs?: number): void {
    if (this.reconnectTimer) return;

    this.reconnectAttempts += 1;
    const isWaitingForQr = this.status !== 'connected';
    // If waiting for QR code to be scanned, always reconnect fast (1s) so a new QR is ready without delay!
    const delay = delayMs !== undefined 
      ? delayMs 
      : isWaitingForQr 
        ? 1000 
        : Math.min(1500 * Math.pow(1.3, this.reconnectAttempts), 25000);
    console.log(`[WhatsAppClient] Reconnecting [${this.sessionId}] in ${(delay / 1000).toFixed(1)}s (attempt ${this.reconnectAttempts})...`);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.init().catch((err) => {
        console.error(`[WhatsAppClient] Auto-reconnect failed for [${this.sessionId}]:`, err.message);
      });
    }, delay);
  }

  /**
   * Ensures that a fresh, active QR code is currently being generated.
   * If the socket connection closed or entered an idle/logged_out state, re-inits cleanly.
   */
  public async ensureQrReady(): Promise<string | null> {
    if (this.status === 'connected') return null;
    if (this.currentQrDataUrl) return this.currentQrDataUrl;

    if (!this.sock || this.status === 'logged_out' || this.status === 'idle' || this.status === 'error') {
      console.log(`[WhatsAppClient] ensureQrReady: Initializing clean socket for [${this.sessionId}]...`);
      if (this.authStateResult) {
        await this.authStateResult.clearVault().catch(() => {});
      }
      await this.init();
    }

    return this.currentQrDataUrl;
  }

  /**
   * Forcibly regenerates a fresh QR code:
   * Cleans up stale unauthenticated socket, purges vault, and returns fresh QR.
   */
  public async refreshQr(): Promise<string | null> {
    if (this.status === 'connected') {
      throw new Error('WhatsApp companion is already connected and active. To link a different account, log out first.');
    }

    console.log(`[WhatsAppClient] Force refreshing QR code for session [${this.sessionId}]...`);
    this.isExplicitDisconnect = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    if (this.sock) {
      this.sock.ev.removeAllListeners('connection.update');
      this.sock.ev.removeAllListeners('creds.update');
      try {
        this.sock.end(undefined);
      } catch {}
      this.sock = null;
    }

    if (this.authStateResult) {
      await this.authStateResult.clearVault().catch(() => {});
    }

    this.currentQrDataUrl = null;
    this.lastPairingCode = null;
    this.reconnectAttempts = 0;
    this.status = 'connecting';
    this.broadcastStatus();

    await this.init();

    // Poll up to 6 seconds for the first QR event from WhatsApp
    return new Promise((resolve) => {
      if (this.currentQrDataUrl) return resolve(this.currentQrDataUrl);

      const checkInterval = setInterval(() => {
        if (this.currentQrDataUrl || this.status === 'connected') {
          clearInterval(checkInterval);
          clearTimeout(timeoutTimer);
          resolve(this.currentQrDataUrl);
        }
      }, 250);

      const timeoutTimer = setTimeout(() => {
        clearInterval(checkInterval);
        resolve(this.currentQrDataUrl);
      }, 6000);
    });
  }

  /**
   * Request an 8-character pairing code for phone-number-based linking
   */
  public async requestPairingCode(phoneNumber: string): Promise<string> {
    if (!this.sock) {
      throw new Error('WhatsApp companion engine is initializing. Please wait 3 seconds and try again.');
    }

    const cleanNumber = phoneNumber.replace(/\D/g, '');
    if (!cleanNumber || cleanNumber.length < 10 || cleanNumber.length > 15) {
      throw new Error('Please enter a valid international phone number with country code (e.g., 919876543210 for India, 14155552671 for US). Must be 10 to 15 digits.');
    }

    if (/^(\d)\1+$/.test(cleanNumber) || cleanNumber === '1234567890' || cleanNumber === '0123456789') {
      throw new Error('Fake or test phone numbers cannot be verified. Please enter your real WhatsApp mobile number.');
    }

    if (this.sock.authState.creds.registered) {
      throw new Error('This session is already registered. To link a new number, reset the vault first.');
    }

    this.status = 'pairing';
    this.broadcastStatus();

    try {
      const code = await this.sock.requestPairingCode(cleanNumber);
      this.lastPairingCode = code;
      this.broadcastStatus();
      console.log(`[WhatsAppClient] Pairing code generated for ${cleanNumber}: ${code}`);
      return code;
    } catch (pairErr: any) {
      console.error('[WhatsAppClient] Failed to request pairing code:', pairErr.message);
      this.status = 'waiting_qr';
      this.broadcastStatus();
      const msg = (pairErr.message || '').toLowerCase();
      if (msg.includes('item-not-found') || msg.includes('bad-request') || msg.includes('400')) {
        throw new Error('WhatsApp server could not generate a code for this number. Please verify that this mobile number is registered on WhatsApp and includes your country code.');
      }
      throw pairErr;
    }
  }

  /**
   * Quick-send a message to any recipient phone or JID
   */
  public async sendMessage(recipient: string, text: string): Promise<any> {
    if (!this.sock || this.status !== 'connected') {
      throw new Error('WhatsApp gateway is not connected. Please ensure session is active.');
    }

    if (!text || !text.trim()) {
      throw new Error('Message text cannot be empty');
    }

    let recipientJid = recipient.trim();
    if (!recipientJid.includes('@')) {
      const cleaned = recipientJid.replace(/\D/g, '');
      if (!cleaned) {
        throw new Error('Invalid recipient phone number');
      }
      recipientJid = `${cleaned}@s.whatsapp.net`;
    }

    const result = await this.sock.sendMessage(recipientJid, { text: text.trim() });
    return result;
  }

  /**
   * Sends a ping to self to verify end-to-end socket liveliness
   */
  public async sendTestPingToSelf(): Promise<any> {
    if (!this.sock || !this.sock.user) {
      throw new Error('Client is not connected. Cannot send test ping.');
    }

    const rawId = this.sock.user.id;
    // Strip device suffix from JID e.g. 12345:12@s.whatsapp.net -> 12345@s.whatsapp.net
    const selfJid = rawId.includes(':')
      ? `${rawId.split(':')[0]}@s.whatsapp.net`
      : rawId;

    const timestamp = new Date().toLocaleString('en-US', { timeZoneName: 'short' });
    const text = `🏓 Pong! WAKeep is active 24/7.\nUptime: ${Math.floor(process.uptime())}s\nVerified at: ${timestamp}`;

    return this.sendMessage(selfJid, text);
  }

  /**
   * Unlinks the WhatsApp account, instructs WhatsApp servers to terminate this device companion,
   * purges all encrypted credentials from Supabase, and halts reconnect loops.
   */
  public async logoutAccount(): Promise<void> {
    this.isExplicitDisconnect = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    try {
      if (this.sock) {
        this.sock.ev.removeAllListeners('connection.update');
        this.sock.ev.removeAllListeners('creds.update');
        try {
          await this.sock.logout('User initiated account logout from WAKeep server');
        } catch (logoutErr: any) {
          console.warn('[WhatsAppClient] Non-fatal sock.logout notice:', logoutErr.message);
        }
        try {
          this.sock.end(undefined);
        } catch {}
        this.sock = null;
      }

      if (this.authStateResult) {
        await this.authStateResult.clearVault();
      }

      this.currentQrDataUrl = null;
      this.lastPairingCode = null;
      this.reconnectAttempts = 0;
      this.status = 'logged_out';
      this.broadcastStatus();

      console.log(`[WhatsAppClient] Session [${this.sessionId}] account successfully logged out and purged from server.`);
    } catch (err: any) {
      console.error('[WhatsAppClient] Error during logoutAccount:', err.message);
      throw err;
    }
  }

  /**
   * Resets the Supabase vault and forces new QR code generation
   */
  public async resetVault(): Promise<void> {
    this.isExplicitDisconnect = true;

    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }

    try {
      if (this.sock) {
        this.sock.ev.removeAllListeners('connection.update');
        this.sock.ev.removeAllListeners('creds.update');
        this.sock.ev.removeAllListeners('messages.upsert');
        try {
          this.sock.end(undefined);
        } catch {}
        this.sock = null;
      }

      if (this.authStateResult) {
        await this.authStateResult.clearVault();
      }

      this.currentQrDataUrl = null;
      this.lastPairingCode = null;
      this.reconnectAttempts = 0;
      this.status = 'idle';
      this.broadcastStatus();

      console.log('[WhatsAppClient] Vault cleared. Reinitializing fresh session...');
      await this.init();
    } catch (resetErr: any) {
      console.error('[WhatsAppClient] Error during vault reset:', resetErr.message);
      throw resetErr;
    }
  }

  /**
   * Cleanly closes the socket
   */
  public async shutdown(): Promise<void> {
    this.isExplicitDisconnect = true;
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
    }
    if (this.authStateResult) {
      await this.authStateResult.flushPendingWrites();
    }
    if (this.sock) {
      try {
        this.sock.end(undefined);
      } catch {}
      this.sock = null;
    }
  }
}
