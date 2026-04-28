import { Request, Response, NextFunction } from 'express';

function sanitizeString(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#x27;')
    .replace(/\//g, '&#x2F;');
}

function sanitizeObject(obj: Record<string, unknown>): Record<string, unknown> {
  const result: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(obj)) {
    if (typeof val === 'string') {
      result[key] = sanitizeString(val);
    } else if (val !== null && typeof val === 'object' && !Array.isArray(val)) {
      result[key] = sanitizeObject(val as Record<string, unknown>);
    } else {
      result[key] = val;
    }
  }
  return result;
}

/**
 * Sanitizes req.body in-place and attaches req.sanitizedQuery with
 * XSS-safe copies of all string query parameters.
 *
 * Controllers should read query params from req.sanitizedQuery instead
 * of req.query to avoid XSS payloads reaching response output.
 */
export const sanitizeInput = (req: Request, _res: Response, next: NextFunction): void => {
  if (req.body && typeof req.body === 'object') {
    req.body = sanitizeObject(req.body as Record<string, unknown>);
  }

  // req.query is a read-only getter in Express 5 — build a sanitized copy
  const sanitizedQuery: Record<string, unknown> = {};
  for (const [key, val] of Object.entries(req.query)) {
    sanitizedQuery[key] = typeof val === 'string' ? sanitizeString(val) : val;
  }
  (req as any).sanitizedQuery = sanitizedQuery;

  next();
};
