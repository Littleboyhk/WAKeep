import crypto from 'crypto';
import { SupabaseClient } from '@supabase/supabase-js';
import { Server as SocketIOServer } from 'socket.io';
import { WhatsAppClientManager } from './whatsappClient.js';
import { decryptPayload, encryptPayload } from '../utils/crypto.js';

export interface SessionMeta {
  sessionId: string;
  passwordHash: string;
  createdAt: string;
  lastLoginAt?: string;
}

export class MultiSessionManager {
  private supabase: SupabaseClient;
  private vaultSecret: string;
  private io: SocketIOServer;
  private adminPassword?: string;
  private defaultSessionId: string;
  private sessions = new Map<string, WhatsAppClientManager>();
  
  // Blacklist of reserved system session names to prevent collision or impersonation
  private static readonly RESERVED_SESSIONS = new Set([
    'main_session', 'admin', 'root', 'system', 'api', 'auth', 'health',
    'config', 'session', 'null', 'undefined', 'administrator', 'vault',
    'supabase', 'render', 'test', 'public', 'private', 'dashboard', 'status'
  ]);

  // Per-session brute-force lockout tracker (session -> { count, lockedUntil })
  private failedLoginAttempts = new Map<string, { count: number; lockedUntil: number }>();

  constructor(options: {
    supabase: SupabaseClient;
    vaultSecret: string;
    io: SocketIOServer;
    adminPassword?: string;
    defaultSessionId?: string;
  }) {
    this.supabase = options.supabase;
    this.vaultSecret = options.vaultSecret;
    this.io = options.io;
    this.adminPassword = options.adminPassword;
    this.defaultSessionId = options.defaultSessionId || 'main_session';
  }

  /**
   * Sanitizes session identifiers to safe alphanumeric strings with dashes/underscores
   */
  public cleanSessionId(raw: string): string {
    if (!raw) return '';
    const cleaned = String(raw).trim().toLowerCase().replace(/[^a-z0-9_-]/g, '');
    return cleaned;
  }

  /**
   * Checks whether a session name is currently locked due to brute-force attempts
   */
  public isSessionLocked(sessionId: string): boolean {
    const record = this.failedLoginAttempts.get(sessionId);
    if (!record) return false;
    if (Date.now() > record.lockedUntil) {
      this.failedLoginAttempts.delete(sessionId);
      return false;
    }
    return record.count >= 5;
  }

  /**
   * Records a failed login attempt; locks the session for 15 minutes after 5 consecutive failures
   */
  public recordFailedLogin(sessionId: string): void {
    const now = Date.now();
    const record = this.failedLoginAttempts.get(sessionId) || { count: 0, lockedUntil: 0 };
    record.count += 1;
    if (record.count >= 5) {
      record.lockedUntil = now + 15 * 60 * 1000; // 15-minute lockout
      console.warn(`🔒 [Security Guard] Session [${sessionId}] locked for 15 minutes due to 5 failed login attempts.`);
    }
    this.failedLoginAttempts.set(sessionId, record);
  }

  /**
   * Clears failed attempt tracking upon successful authentication
   */
  public clearFailedLogin(sessionId: string): void {
    this.failedLoginAttempts.delete(sessionId);
  }

  /**
   * Generates a salted SHA-256 HMAC hash of the user's password
   */
  public hashPassword(password: string): string {
    return crypto
      .createHmac('sha256', this.vaultSecret)
      .update(String(password).trim())
      .digest('hex');
  }

  /**
   * Constant-time comparison between two string digests
   */
  public compareHashes(a: string, b: string): boolean {
    const bufA = crypto.createHash('sha256').update(a).digest();
    const bufB = crypto.createHash('sha256').update(b).digest();
    return crypto.timingSafeEqual(bufA, bufB);
  }

  /**
   * Initializes the manager on server startup:
   * 1. Resumes the default primary session
   * 2. Scans Supabase for any other previously registered user sessions
   */
  public async init(): Promise<void> {
    console.log('[MultiSessionManager] Initializing Multi-Session Hub...');

    // Always start the primary default session
    await this.getOrLoadSession(this.defaultSessionId);

    // Discover any other sessions with stored credentials in Supabase
    try {
      const { data, error } = await this.supabase
        .from('wa_auth_vault')
        .select('id')
        .like('id', '%:creds');

      if (!error && data && data.length > 0) {
        for (const row of data) {
          const parts = row.id.split(':');
          const sid = parts[0];
          if (sid && sid !== this.defaultSessionId && !this.sessions.has(sid)) {
            console.log(`[MultiSessionManager] Restoring background keep-alive for registered session: ${sid}`);
            await this.getOrLoadSession(sid);
          }
        }
      }
    } catch (err: any) {
      console.warn('[MultiSessionManager] Non-fatal: could not auto-discover previous sessions:', err.message);
    }
  }

  /**
   * Retrieves an in-memory session manager, or restores it from Supabase
   */
  public async getOrLoadSession(rawSessionId: string): Promise<WhatsAppClientManager> {
    const sessionId = this.cleanSessionId(rawSessionId) || this.defaultSessionId;

    if (this.sessions.has(sessionId)) {
      return this.sessions.get(sessionId)!;
    }

    const manager = new WhatsAppClientManager({
      supabase: this.supabase,
      vaultSecret: this.vaultSecret,
      sessionId,
      io: this.io
    });

    this.sessions.set(sessionId, manager);

    // Start Baileys connection
    manager.init().catch((err) => {
      console.error(`[MultiSessionManager] Error starting session [${sessionId}]:`, err.message);
    });

    return manager;
  }

  /**
   * Retrieves an active session manager if already loaded in memory
   */
  public getSession(rawSessionId: string): WhatsAppClientManager | undefined {
    const sessionId = this.cleanSessionId(rawSessionId) || this.defaultSessionId;
    return this.sessions.get(sessionId);
  }

  /**
   * Creates a brand new user session with a private 8+ character password
   * Hardened against session hijacking and reserved name collisions
   */
  public async createSession(
    rawSessionId: string,
    password: string
  ): Promise<{ manager: WhatsAppClientManager; sessionId: string }> {
    const sessionId = this.cleanSessionId(rawSessionId);

    if (!sessionId || sessionId.length < 3 || sessionId.length > 32) {
      throw new Error('Session Name must be between 3 and 32 alphanumeric characters.');
    }

    // Block collision with reserved system names
    if (MultiSessionManager.RESERVED_SESSIONS.has(sessionId)) {
      throw new Error(`The session name "${sessionId}" is reserved. Please choose a custom name.`);
    }

    const trimmedPassword = String(password).trim();
    if (!trimmedPassword || trimmedPassword.length < 8) {
      throw new Error('Password must be at least 8 characters long.');
    }

    const commonWeak = ['password', '12345678', 'qwerty123', 'admin123', 'password123', 'whatsapp', 'wakeep123'];
    if (commonWeak.includes(trimmedPassword.toLowerCase())) {
      throw new Error('Please choose a stronger password (avoid common dictionary words or simple number sequences).');
    }

    // 1. Check in-memory active sessions
    if (this.sessions.has(sessionId)) {
      throw new Error(
        `Session name "${sessionId}" is already registered. Please choose a different name or log into your existing session.`
      );
    }

    // 2. Check if session metadata OR active credentials already exist in Supabase vault
    const metaVaultId = `${sessionId}:__session_meta`;
    const credsVaultId = `${sessionId}:creds`;
    const { data: existingRows } = await this.supabase
      .from('wa_auth_vault')
      .select('id')
      .in('id', [metaVaultId, credsVaultId]);

    if (existingRows && existingRows.length > 0) {
      throw new Error(
        `Session name "${sessionId}" is already registered. Please choose a different name or log into your existing session.`
      );
    }

    // Store encrypted session metadata
    const passwordHash = this.hashPassword(trimmedPassword);
    const metaPayload: SessionMeta = {
      sessionId,
      passwordHash,
      createdAt: new Date().toISOString()
    };

    const encryptedMeta = encryptPayload(JSON.stringify(metaPayload), this.vaultSecret);
    await this.supabase.from('wa_auth_vault').upsert({
      id: metaVaultId,
      encrypted_payload: encryptedMeta,
      updated_at: new Date().toISOString()
    });

    // Initialize fresh WhatsApp client for this new session
    const manager = await this.getOrLoadSession(sessionId);

    return { manager, sessionId };
  }

  /**
   * Verifies credentials and unlocks an existing user session
   * Hardened against brute force, user enumeration, and timing attacks
   */
  public async loginSession(
    rawSessionId: string,
    password: string
  ): Promise<{ manager: WhatsAppClientManager; sessionId: string }> {
    const sessionId = this.cleanSessionId(rawSessionId) || this.defaultSessionId;

    // Check brute force lockout
    if (this.isSessionLocked(sessionId)) {
      throw new Error('Too many failed login attempts for this session. Temporarily locked for 15 minutes to protect your account.');
    }

    if (!password || String(password).trim().length < 8) {
      this.recordFailedLogin(sessionId);
      throw new Error('Invalid session name or password. Access denied.');
    }

    const trimmedPassword = String(password).trim();

    // Special check for primary default session (matches ADMIN_PASSWORD)
    if (sessionId === this.defaultSessionId && this.adminPassword) {
      const match = this.compareHashes(trimmedPassword, this.adminPassword);
      if (!match) {
        this.recordFailedLogin(sessionId);
        throw new Error('Invalid session name or password. Access denied.');
      }
      this.clearFailedLogin(sessionId);
      const manager = await this.getOrLoadSession(sessionId);
      return { manager, sessionId };
    }

    // Retrieve encrypted session metadata
    const metaVaultId = `${sessionId}:__session_meta`;
    const { data: metaRecord, error } = await this.supabase
      .from('wa_auth_vault')
      .select('id, encrypted_payload')
      .eq('id', metaVaultId)
      .maybeSingle();

    if (error || !metaRecord || !metaRecord.encrypted_payload) {
      // Check legacy credentials
      const credsVaultId = `${sessionId}:creds`;
      const { data: credsRecord } = await this.supabase
        .from('wa_auth_vault')
        .select('id')
        .eq('id', credsVaultId)
        .maybeSingle();

      if (credsRecord && this.adminPassword && this.compareHashes(trimmedPassword, this.adminPassword)) {
        this.clearFailedLogin(sessionId);
        const manager = await this.getOrLoadSession(sessionId);
        return { manager, sessionId };
      }

      // Timing-safe dummy comparison to mitigate timing attacks
      this.compareHashes(this.hashPassword(trimmedPassword), this.hashPassword('dummy_constant_timing_hash'));
      this.recordFailedLogin(sessionId);
      throw new Error('Invalid session name or password. Access denied.');
    }

    try {
      const decrypted = decryptPayload(metaRecord.encrypted_payload, this.vaultSecret);
      const meta: SessionMeta = JSON.parse(decrypted);

      const targetHash = this.hashPassword(trimmedPassword);
      const isMatch = this.compareHashes(targetHash, meta.passwordHash);

      if (!isMatch) {
        this.recordFailedLogin(sessionId);
        throw new Error('Invalid session name or password. Access denied.');
      }

      this.clearFailedLogin(sessionId);
      const manager = await this.getOrLoadSession(sessionId);
      return { manager, sessionId };
    } catch (parseErr: any) {
      this.recordFailedLogin(sessionId);
      throw new Error('Invalid session name or password. Access denied.');
    }
  }

  /**
   * Returns current count of active in-memory sessions
   */
  public getActiveSessionsCount(): number {
    return this.sessions.size;
  }

  /**
   * Returns telemetry summaries for all loaded sessions
   */
  public getSessionsSummary() {
    const list: Array<{ sessionId: string; status: string; phone?: string | null }> = [];
    for (const [id, mgr] of this.sessions.entries()) {
      const user = mgr.getUserProfile();
      list.push({
        sessionId: id,
        status: mgr.getStatus(),
        phone: user?.phone || null
      });
    }
    return list;
  }

  /**
   * Unlinks the WhatsApp account, instructs WhatsApp servers to terminate this device companion,
   * wipes all encrypted session credentials from Supabase, and halts reconnect loops.
   */
  public async logoutAndRemoveSession(rawSessionId: string): Promise<void> {
    const sessionId = this.cleanSessionId(rawSessionId) || this.defaultSessionId;
    console.log(`[MultiSessionManager] Logging out and purging session [${sessionId}]...`);

    const manager = this.sessions.get(sessionId);
    if (manager) {
      await manager.logoutAccount();
      if (sessionId !== this.defaultSessionId) {
        this.sessions.delete(sessionId);
      }
    }

    // Purge session metadata and all related keys from Supabase
    try {
      if (sessionId !== this.defaultSessionId) {
        await this.supabase.from('wa_auth_vault').delete().eq('id', `${sessionId}:__session_meta`);
      }
      await this.supabase.from('wa_auth_vault').delete().like('id', `${sessionId}:%`);
    } catch (dbErr: any) {
      console.warn(`[MultiSessionManager] Non-fatal vault purge notice for [${sessionId}]:`, dbErr.message);
    }
  }

  /**
   * Graceful shutdown of all active sessions
   */
  public async shutdownAll(): Promise<void> {
    console.log('[MultiSessionManager] Shutting down all active sessions...');
    const promises: Promise<void>[] = [];
    for (const manager of this.sessions.values()) {
      promises.push(manager.shutdown());
    }
    await Promise.allSettled(promises);
    this.sessions.clear();
  }
}
