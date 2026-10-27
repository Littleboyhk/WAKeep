import { Boom } from '@hapi/boom';
import { SupabaseClient } from '@supabase/supabase-js';
import makeWASocket, {
  ConnectionState,
  DisconnectReason,
  fetchLatestBaileysVersion,
  proto,
  WASocket,
  WAMessage
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

  private broadcastStatus() {
    if (!this.io) return;
    const telemetry = this.getTelemetry();
    this.io.to('authenticated').emit('session_status', {
      ...telemetry,
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
        version: [2, 3000, 1015901307] as [number, number, number],
        isLatest: true
      }));

      console.log(`[WhatsAppClient] Starting socket with Baileys v${version.join('.')} (latest: ${isLatest})`);

      // Create socket with anti-disconnect, low-RAM, and desktop spoofing options
      this.sock = makeWASocket({
        version,
        auth: this.authStateResult.state,
        logger: pino({ level: 'silent' }),
        printQRInTerminal: false,
        // Desktop fingerprint signature: Ubuntu Chrome
        browser: ['Ubuntu', 'Chrome', '128.0.6613.119'],
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
          console.log('[WhatsAppClient] New QR code generated');
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

        console.log(`[WhatsAppClient] Connection closed. Reason: ${reason} (${statusCode})`);

        this.currentQrDataUrl = null;

        if (this.isExplicitDisconnect) {
          this.status = 'idle';
          this.broadcastStatus();
          return;
        }

        if (statusCode === DisconnectReason.loggedOut) {
          this.status = 'logged_out';
          console.warn('[WhatsAppClient] Session was logged out by WhatsApp. Requires new QR/pairing.');
          this.broadcastStatus();
        } else {
          this.status = 'reconnecting';
          this.broadcastStatus();
          this.scheduleReconnect();
        }
      }
    });

    // Incoming & Outgoing Messages
    this.sock.ev.on('messages.upsert', async ({ messages, type }) => {
      if (type !== 'notify' && type !== 'append') return;

      for (const msg of messages) {
        if (!msg.message || !msg.key.remoteJid) continue;

        // Skip status broadcasts
        if (msg.key.remoteJid === 'status@broadcast') continue;

        const summary = this.extractMessageSummary(msg);
        if (summary) {
          await this.persistMessage(summary);
          if (this.io) {
            this.io.to('authenticated').emit('new_message', summary);
          }
        }
      }
    });
  }

  private extractMessageSummary(msg: WAMessage): ChatMessageSummary | null {
    const key = msg.key;
    if (!key.id || !key.remoteJid) return null;

    const messageContent = msg.message;
    let text = '';

    if (messageContent) {
      if (messageContent.conversation) {
        text = messageContent.conversation;
      } else if (messageContent.extendedTextMessage?.text) {
        text = messageContent.extendedTextMessage.text;
      } else if (messageContent.imageMessage?.caption) {
        text = `📷 ${messageContent.imageMessage.caption}`;
      } else if (messageContent.imageMessage) {
        text = '📷 Photo';
      } else if (messageContent.videoMessage?.caption) {
        text = `🎥 ${messageContent.videoMessage.caption}`;
      } else if (messageContent.videoMessage) {
        text = '🎥 Video';
      } else if (messageContent.documentMessage?.title) {
        text = `📄 ${messageContent.documentMessage.title}`;
      } else if (messageContent.documentMessage) {
        text = '📄 Document';
      } else if (messageContent.audioMessage) {
        text = '🎵 Voice message';
      } else if (messageContent.contactMessage?.displayName) {
        text = `👤 Contact: ${messageContent.contactMessage.displayName}`;
      } else if (messageContent.locationMessage) {
        text = '📍 Location pin';
      } else {
        const types = Object.keys(messageContent).filter(k => k !== 'messageContextInfo');
        text = types.length > 0 ? `[${types[0]}]` : '[Message]';
      }
    }

    const fromMe = Boolean(key.fromMe);
    const chatJid = key.remoteJid;
    const senderJid = key.participant || (fromMe ? (this.sock?.user?.id || 'me') : chatJid);
    const senderName = msg.pushName || (fromMe ? 'You' : '');
    const timestampNumber = typeof msg.messageTimestamp === 'number'
      ? msg.messageTimestamp
      : typeof msg.messageTimestamp?.low === 'number'
      ? msg.messageTimestamp.low
      : Math.floor(Date.now() / 1000);

    return {
      message_id: key.id,
      chat_jid: chatJid,
      sender_jid: senderJid,
      sender_name: senderName,
      from_me: fromMe,
      text_content: text,
      message_timestamp: timestampNumber
    };
  }

  private async persistMessage(summary: ChatMessageSummary): Promise<void> {
    try {
      await this.supabase.from('wa_recent_messages').upsert(
        {
          message_id: summary.message_id,
          chat_jid: summary.chat_jid,
          sender_jid: summary.sender_jid,
          sender_name: summary.sender_name,
          from_me: summary.from_me,
          text_content: summary.text_content,
          message_timestamp: summary.message_timestamp
        },
        { onConflict: 'message_id' }
      );
    } catch (dbErr: any) {
      console.warn('[WhatsAppClient] Non-fatal: could not persist message to Supabase:', dbErr.message);
    }
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;

    this.reconnectAttempts += 1;
    // Exponential backoff capped at 30 seconds
    const delay = Math.min(2000 * Math.pow(1.4, this.reconnectAttempts), 30000);
    console.log(`[WhatsAppClient] Reconnecting in ${(delay / 1000).toFixed(1)}s (attempt ${this.reconnectAttempts})...`);

    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.init().catch((err) => {
        console.error('[WhatsAppClient] Auto-reconnect failed:', err);
      });
    }, delay);
  }

  /**
   * Request an 8-character pairing code for phone-number-based linking
   */
  public async requestPairingCode(phoneNumber: string): Promise<string> {
    if (!this.sock) {
      throw new Error('WhatsApp client is not initialized. Please wait for initial setup.');
    }

    const cleanNumber = phoneNumber.replace(/\D/g, '');
    if (!cleanNumber || cleanNumber.length < 8 || cleanNumber.length > 15) {
      throw new Error('Please enter a valid international phone number with country code (e.g., 14155552671)');
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
