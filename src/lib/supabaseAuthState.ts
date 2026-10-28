import { SupabaseClient } from '@supabase/supabase-js';
import {
  AuthenticationCreds,
  AuthenticationState,
  BufferJSON,
  initAuthCreds,
  proto,
  SignalDataTypeMap
} from '@whiskeysockets/baileys';
import { decryptPayload, encryptPayload } from '../utils/crypto.js';

interface SupabaseAuthVaultRow {
  id: string;
  encrypted_payload: string;
  updated_at?: string;
}

export interface SupabaseAuthStateResult {
  state: AuthenticationState;
  saveCreds: () => Promise<void>;
  flushPendingWrites: () => Promise<void>;
  clearVault: () => Promise<void>;
}

/**
 * Custom encrypted Supabase Auth State adapter for Baileys.
 * Encrypts all session credentials and keys with AES-256-GCM.
 * Includes an in-memory cache and debounced batch-writing to protect against Supabase rate limits.
 */
export async function useSupabaseAuthState(
  supabase: SupabaseClient,
  vaultSecret: string,
  sessionId = 'main_session'
): Promise<SupabaseAuthStateResult> {
  // In-memory key-value cache to prevent duplicate queries and cache unwritten updates
  const memoryCache = new Map<string, any>();
  const pendingWrites = new Map<string, string>(); // vaultId -> encrypted_payload
  const pendingDeletes = new Set<string>(); // vaultId
  let flushTimeout: NodeJS.Timeout | null = null;
  const DEBOUNCE_MS = 400;

  const buildVaultId = (fileName: string): string => {
    const sanitized = fileName.replace(/\//g, '__').replace(/:/g, '-');
    return `${sessionId}:${sanitized}`;
  };

  /**
   * Flushes all debounced writes and deletions to Supabase in batches.
   */
  const flushPendingWrites = async (): Promise<void> => {
    if (flushTimeout) {
      clearTimeout(flushTimeout);
      flushTimeout = null;
    }

    // Flush batch writes
    if (pendingWrites.size > 0) {
      const recordsToUpsert: SupabaseAuthVaultRow[] = [];
      for (const [id, encrypted_payload] of pendingWrites.entries()) {
        recordsToUpsert.push({
          id,
          encrypted_payload,
          updated_at: new Date().toISOString()
        });
      }
      pendingWrites.clear();

      // Chunk into blocks of 50 to avoid massive payloads
      const CHUNK_SIZE = 50;
      for (let i = 0; i < recordsToUpsert.length; i += CHUNK_SIZE) {
        const chunk = recordsToUpsert.slice(i, i + CHUNK_SIZE);
        const { error } = await supabase.from('wa_auth_vault').upsert(chunk, { onConflict: 'id' });
        if (error) {
          console.error('[SupabaseAuthState] Error upserting vault records:', error.message);
        }
      }
    }

    // Flush batch deletes
    if (pendingDeletes.size > 0) {
      const idsToDelete = Array.from(pendingDeletes);
      pendingDeletes.clear();

      const CHUNK_SIZE = 50;
      for (let i = 0; i < idsToDelete.length; i += CHUNK_SIZE) {
        const chunk = idsToDelete.slice(i, i + CHUNK_SIZE);
        const { error } = await supabase.from('wa_auth_vault').delete().in('id', chunk);
        if (error) {
          console.error('[SupabaseAuthState] Error deleting vault records:', error.message);
        }
      }
    }
  };

  const scheduleFlush = () => {
    if (flushTimeout) return;
    flushTimeout = setTimeout(() => {
      flushPendingWrites().catch((err) => {
        console.error('[SupabaseAuthState] Scheduled flush failed:', err);
      });
    }, DEBOUNCE_MS);
  };

  const writeData = async (data: any, fileName: string): Promise<void> => {
    const vaultId = buildVaultId(fileName);
    memoryCache.set(vaultId, data);
    pendingDeletes.delete(vaultId);

    const serialized = JSON.stringify(data, BufferJSON.replacer);
    const encrypted = encryptPayload(serialized, vaultSecret);
    pendingWrites.set(vaultId, encrypted);

    scheduleFlush();
  };

  const readData = async (fileName: string): Promise<any> => {
    const vaultId = buildVaultId(fileName);

    if (pendingDeletes.has(vaultId)) {
      return null;
    }

    if (memoryCache.has(vaultId)) {
      return memoryCache.get(vaultId);
    }

    try {
      const { data, error } = await supabase
        .from('wa_auth_vault')
        .select('id, encrypted_payload')
        .eq('id', vaultId)
        .maybeSingle();

      if (error || !data || !data.encrypted_payload) {
        return null;
      }

      const decrypted = decryptPayload(data.encrypted_payload, vaultSecret);
      const parsed = JSON.parse(decrypted, BufferJSON.reviver);
      memoryCache.set(vaultId, parsed);
      return parsed;
    } catch (err: any) {
      console.error(`[SupabaseAuthState] Failed to read or decrypt key ${vaultId}:`, err.message);
      return null;
    }
  };

  const removeData = async (fileName: string): Promise<void> => {
    const vaultId = buildVaultId(fileName);
    memoryCache.delete(vaultId);
    pendingWrites.delete(vaultId);
    pendingDeletes.add(vaultId);

    scheduleFlush();
  };

  // Load existing credentials or initialize new ones
  const rawCreds = await readData('creds.json');
  const creds: AuthenticationCreds = rawCreds || initAuthCreds();

  const state: AuthenticationState = {
    creds,
    keys: {
      get: async <T extends keyof SignalDataTypeMap>(
        type: T,
        ids: string[]
      ): Promise<{ [key: string]: SignalDataTypeMap[T] }> => {
        const result: { [key: string]: SignalDataTypeMap[T] } = {};
        const missingIds: string[] = [];

        // Check in-memory cache first
        for (const id of ids) {
          const fileName = `${type}-${id}.json`;
          const vaultId = buildVaultId(fileName);

          if (pendingDeletes.has(vaultId)) {
            continue;
          }

          if (memoryCache.has(vaultId)) {
            let val = memoryCache.get(vaultId);
            if (type === 'app-state-sync-key' && val) {
              val = proto.Message.AppStateSyncKeyData.fromObject(val);
            }
            result[id] = val;
          } else {
            missingIds.push(id);
          }
        }

        // Fetch remaining keys from Supabase in a single batch query
        if (missingIds.length > 0) {
          const vaultIds = missingIds.map((id) => buildVaultId(`${type}-${id}.json`));
          try {
            const { data, error } = await supabase
              .from('wa_auth_vault')
              .select('id, encrypted_payload')
              .in('id', vaultIds);

            if (!error && data) {
              const loadedMap = new Map<string, string>();
              for (const row of data) {
                loadedMap.set(row.id, row.encrypted_payload);
              }

              for (const id of missingIds) {
                const vaultId = buildVaultId(`${type}-${id}.json`);
                const payload = loadedMap.get(vaultId);

                if (payload) {
                  try {
                    const decrypted = decryptPayload(payload, vaultSecret);
                    let parsed = JSON.parse(decrypted, BufferJSON.reviver);
                    memoryCache.set(vaultId, parsed);

                    if (type === 'app-state-sync-key' && parsed) {
                      parsed = proto.Message.AppStateSyncKeyData.fromObject(parsed);
                    }
                    result[id] = parsed;
                  } catch (decryptErr: any) {
                    console.error(`[SupabaseAuthState] Error decrypting key ${vaultId}:`, decryptErr.message);
                  }
                }
              }
            }
          } catch (fetchErr: any) {
            console.error('[SupabaseAuthState] Error fetching keys batch:', fetchErr.message);
          }
        }

        return result;
      },
      set: async (data: any): Promise<void> => {
        for (const category in data) {
          const categoryEntries = data[category];
          for (const id in categoryEntries) {
            const value = categoryEntries[id];
            const fileName = `${category}-${id}.json`;
            if (value) {
              await writeData(value, fileName);
            } else {
              await removeData(fileName);
            }
          }
        }
      }
    }
  };

  const saveCreds = async (): Promise<void> => {
    await writeData(creds, 'creds.json');
    // Ensure creds are flushed immediately so restarts retain session
    await flushPendingWrites();
  };

  const clearVault = async (): Promise<void> => {
    if (flushTimeout) {
      clearTimeout(flushTimeout);
      flushTimeout = null;
    }
    memoryCache.clear();
    pendingWrites.clear();
    pendingDeletes.clear();

    const safePrefix = sessionId.replace(/[_%\\]/g, '\\$&');
    const { error } = await supabase
      .from('wa_auth_vault')
      .delete()
      .like('id', `${safePrefix}:%`);

    if (error) {
      console.error('[SupabaseAuthState] Error clearing session vault:', error.message);
      throw error;
    }
  };

  return {
    state,
    saveCreds,
    flushPendingWrites,
    clearVault
  };
}
