import { createCipheriv, createDecipheriv, randomBytes } from 'crypto';

const ALGORITHM = 'aes-256-gcm';
const CACHE_TTL_MS = 5 * 60 * 1000; // 5 minutes

export interface KeyVersion {
  version: string;
  key: Buffer;
}

export interface Keyset {
  currentVersion: string;
  keys: Record<string, KeyVersion>;
}

interface CachedKeyset {
  keyset: Keyset;
  cachedAt: number;
}

let cache: CachedKeyset | null = null;

function loadKeysetFromEnv(): Keyset {
  const raw = process.env.PII_ENCRYPTION_KEYS;
  if (!raw) {
    throw new Error('PII_ENCRYPTION_KEYS environment variable is not set');
  }

  // Expected format: JSON { currentVersion, keys: { v1: "<hex>", v2: "<hex>" } }
  const parsed = JSON.parse(raw) as { currentVersion: string; keys: Record<string, string> };

  const keys: Record<string, KeyVersion> = {};
  for (const [version, hexKey] of Object.entries(parsed.keys)) {
    keys[version] = { version, key: Buffer.from(hexKey, 'hex') };
  }

  return { currentVersion: parsed.currentVersion, keys };
}

/**
 * Returns the active keyset, refreshing from the environment if the
 * cached copy is older than CACHE_TTL_MS (5 minutes) or forceRefresh is true.
 *
 * This ensures key rotations applied to PII_ENCRYPTION_KEYS (e.g. via
 * AWS Secrets Manager) are picked up within 5 minutes without a restart.
 */
export async function getKeyset(forceRefresh = false): Promise<Keyset> {
  const now = Date.now();
  if (!forceRefresh && cache && now - cache.cachedAt < CACHE_TTL_MS) {
    return cache.keyset;
  }

  const keyset = loadKeysetFromEnv();
  cache = { keyset, cachedAt: now };

  console.info('[EncryptionUtil] Encryption keyset loaded', { version: keyset.currentVersion });

  return keyset;
}

/** Clears the keyset cache, forcing the next call to getKeyset() to reload. */
export function clearCache(): void {
  cache = null;
}

export async function encrypt(plaintext: string): Promise<string> {
  const keyset = await getKeyset();
  const { key, version } = keyset.keys[keyset.currentVersion];

  const iv = randomBytes(12);
  const cipher = createCipheriv(ALGORITHM, key, iv);
  const encrypted = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const authTag = cipher.getAuthTag();

  // Format: version:iv(hex):authTag(hex):ciphertext(hex)
  return `${version}:${iv.toString('hex')}:${authTag.toString('hex')}:${encrypted.toString('hex')}`;
}

export async function decrypt(ciphertext: string): Promise<string> {
  const [version, ivHex, authTagHex, dataHex] = ciphertext.split(':');
  if (!version || !ivHex || !authTagHex || !dataHex) {
    throw new Error('Invalid ciphertext format');
  }

  const keyset = await getKeyset();
  const keyVersion = keyset.keys[version];
  if (!keyVersion) {
    throw new Error(`Unknown key version: ${version}`);
  }

  const decipher = createDecipheriv(ALGORITHM, keyVersion.key, Buffer.from(ivHex, 'hex'));
  decipher.setAuthTag(Buffer.from(authTagHex, 'hex'));

  const decrypted = Buffer.concat([
    decipher.update(Buffer.from(dataHex, 'hex')),
    decipher.final(),
  ]);

  return decrypted.toString('utf8');
}
