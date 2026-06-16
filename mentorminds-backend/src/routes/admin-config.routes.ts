import { Router, Request, Response } from 'express';
import { clearCache, getKeyset } from '../utils/encryption.utils';

const router = Router();

/**
 * POST /admin/config/rotate-encryption-key
 *
 * Clears the in-memory keyset cache so the next encryption/decryption
 * call reloads PII_ENCRYPTION_KEYS from the environment (or Secrets Manager).
 * Call this after updating the key in AWS Secrets Manager and reinjecting
 * the env var into the running process.
 */
router.post('/rotate-encryption-key', async (_req: Request, res: Response) => {
  clearCache();

  try {
    // Eagerly reload to validate the new key is readable
    const keyset = await getKeyset(true);
    res.json({ success: true, currentVersion: keyset.currentVersion });
  } catch (err: any) {
    res.status(500).json({ success: false, error: err.message });
  }
});

export default router;
