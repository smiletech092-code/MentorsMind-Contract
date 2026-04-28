import { Pool } from 'pg';

export interface IpRuleData {
  ipRange: string;
  ruleType: 'allow' | 'block';
  context: string;
}

export interface IpRule extends IpRuleData {
  id: number;
  createdAt: Date;
}

export class IpFilterService {
  constructor(private readonly pool: Pool) {}

  /**
   * Adds a new IP rule, rejecting duplicates on (ip_range, rule_type, context).
   *
   * Throws if an identical rule already exists to prevent duplicate entries
   * that would clutter the blocklist and slow down matchIp lookups.
   */
  async addRule(data: IpRuleData): Promise<IpRule> {
    const existing = await this.pool.query<{ id: number }>(
      `SELECT id FROM ip_rules WHERE ip_range = $1 AND rule_type = $2 AND context = $3`,
      [data.ipRange, data.ruleType, data.context]
    );

    if (existing.rows.length > 0) {
      throw new Error(`Rule for ${data.ipRange} already exists`);
    }

    const { rows } = await this.pool.query<IpRule>(
      `INSERT INTO ip_rules (ip_range, rule_type, context, created_at)
       VALUES ($1, $2, $3, NOW())
       RETURNING *`,
      [data.ipRange, data.ruleType, data.context]
    );

    return rows[0];
  }

  async matchIp(ip: string, context: string): Promise<IpRule | null> {
    const { rows } = await this.pool.query<IpRule>(
      `SELECT * FROM ip_rules
       WHERE $1::inet <<= ip_range::inet AND context = $2
       LIMIT 1`,
      [ip, context]
    );
    return rows[0] ?? null;
  }
}
