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
   */
  public async createSession(
    rawSessionId: string,
    password: string
  ): Promise<{ manager: WhatsAppClientManager; sessionId: string }> {
    const sessionId = this.cleanSessionId(rawSessionId);

    if (!sessionId || sessionId.length < 3) {
      throw new Error('Session ID must be between 3 and 32 alphanumeric characters.');
    }

    if (sessionId.length > 32) {
      throw new Error('Session ID cannot exceed 32 characters.');
    }

    if (!password || String(password).trim().length < 8) {
      throw new Error('Password must be at least 8 characters long.');
    }

    // Check if session metadata already exists in the Supabase vault
    const metaVaultId = `${sessionId}:__session_meta`;
    const { data: existingMeta } = await this.supabase
      .from('wa_auth_vault')
      .select('id, encrypted_payload')
      .eq('id', metaVaultId)
      .maybeSingle();

    if (existingMeta && existingMeta.encrypted_payload) {
      throw new Error(
        `Session name "${sessionId}" is already registered. Please choose a different name or log into your existing session.`
      );
    }

    // Store encrypted session metadata
    const passwordHash = this.hashPassword(password);
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
   */
  public async loginSession(
    rawSessionId: string,
    password: string
  ): Promise<{ manager: WhatsAppClientManager; sessionId: string }> {
    const sessionId = this.cleanSessionId(rawSessionId) || this.defaultSessionId;

    if (!password || String(password).trim().length < 8) {
      throw new Error('Password must be at least 8 characters long.');
    }

    const trimmedPassword = String(password).trim();

    // Special check for primary default session (matches ADMIN_PASSWORD)
    if (sessionId === this.defaultSessionId && this.adminPassword) {
      const match = this.compareHashes(trimmedPassword, this.adminPassword);
      if (!match) {
        throw new Error('Invalid password for default session.');
      }
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
      // Check if session has credentials but no metadata (e.g., created earlier)
      const credsVaultId = `${sessionId}:creds`;
      const { data: credsRecord } = await this.supabase
        .from('wa_auth_vault')
        .select('id')
        .eq('id', credsVaultId)
        .maybeSingle();

      if (credsRecord && this.adminPassword && this.compareHashes(trimmedPassword, this.adminPassword)) {
        const manager = await this.getOrLoadSession(sessionId);
        return { manager, sessionId };
      }

      throw new Error(`Session "${sessionId}" does not exist. Please create a new session first.`);
    }

    try {
      const decrypted = decryptPayload(metaRecord.encrypted_payload, this.vaultSecret);
      const meta: SessionMeta = JSON.parse(decrypted);

      const targetHash = this.hashPassword(trimmedPassword);
      const isMatch = this.compareHashes(targetHash, meta.passwordHash);

      if (!isMatch) {
        throw new Error('Invalid password for this session.');
      }

      const manager = await this.getOrLoadSession(sessionId);
      return { manager, sessionId };
    } catch (parseErr: any) {
      if (parseErr.message.includes('Invalid password')) {
        throw parseErr;
      }
      throw new Error('Session authentication failed.');
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
