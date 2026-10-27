import crypto from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const IV_LENGTH = 12; // Standard 96-bit IV recommended for AES-GCM

/**
 * Derives a consistent 32-byte Buffer from the provided secret string.
 * Supports 64-character hex strings or arbitrary strings hashed with SHA-256.
 */
export function getVaultKey(secret: string): Buffer {
  if (!secret) {
    throw new Error('VAULT_SECRET_KEY is required for encrypted storage');
  }

  const trimmed = secret.trim();
  if (/^[0-9a-fA-F]{64}$/.test(trimmed)) {
    return Buffer.from(trimmed, 'hex');
  }

  // Derive 32 bytes via SHA-256 for strings not in 64-character hex format
  return crypto.createHash('sha256').update(trimmed).digest();
}

/**
 * Encrypts a plaintext string using AES-256-GCM.
 * Returns formatted string: "iv:authTag:cipherText" in hexadecimal.
 */
export function encryptPayload(plaintext: string, secretKey: string | Buffer): string {
  const key = typeof secretKey === 'string' ? getVaultKey(secretKey) : secretKey;
  const iv = crypto.randomBytes(IV_LENGTH);

  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  let encrypted = cipher.update(plaintext, 'utf8', 'hex');
  encrypted += cipher.final('hex');

  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

/**
 * Decrypts a formatted "iv:authTag:cipherText" string using AES-256-GCM.
 * Throws an error if decryption or authentication tag verification fails.
 */
export function decryptPayload(encryptedPayload: string, secretKey: string | Buffer): string {
  const parts = encryptedPayload.split(':');
  if (parts.length !== 3) {
    throw new Error('Invalid encrypted payload format. Expected iv:authTag:cipherText');
  }

  const [ivHex, authTagHex, cipherTextHex] = parts;
  const key = typeof secretKey === 'string' ? getVaultKey(secretKey) : secretKey;
  const iv = Buffer.from(ivHex, 'hex');
  const authTag = Buffer.from(authTagHex, 'hex');

  const decipher = crypto.createDecipheriv(ALGORITHM, key, iv);
  decipher.setAuthTag(authTag);

  let decrypted = decipher.update(cipherTextHex, 'hex', 'utf8');
  decrypted += decipher.final('utf8');

  return decrypted;
}
