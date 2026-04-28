import { Pool } from 'pg';

export class AuditLoggerService {
  constructor(private readonly pool: Pool) {}

  /**
   * Deletes audit log entries older than retentionDays days.
   *
   * Uses arithmetic multiplication ($1 * INTERVAL '1 day') instead of
   * string concatenation to prevent SQL injection — PostgreSQL only
   * accepts a numeric multiplier here, so arbitrary strings cannot be
   * injected.
   */
  async cleanupOldLogs(retentionDays: number): Promise<number> {
    if (!Number.isInteger(retentionDays) || retentionDays < 1) {
      throw new Error('Invalid retention days: must be a positive integer');
    }

    const query = `
      DELETE FROM audit_logs
      WHERE created_at < NOW() - ($1 * INTERVAL '1 day')
    `;
    const { rowCount } = await this.pool.query(query, [retentionDays]);
    return rowCount ?? 0;
  }
}
