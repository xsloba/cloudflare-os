// Deployment usage session types. This JSDoc is the agent's API documentation.

/** Aggregated AI usage for one user over the queried period. */
export interface UserUsage {
  /** User id (email) as recorded on each AI request. */
  user: string;
  /** Total cost in USD. */
  cost: number;
  /** Number of AI requests. */
  requests: number;
  /** Total input tokens. */
  tokensIn: number;
  /** Total output tokens. */
  tokensOut: number;
  /** Distinct sessions (chats or gadget runs) with at least one request in the period. */
  sessions: number;
  /** Cost in USD broken down by model id. */
  costByModel: Record<string, number>;
}

/** Aggregated usage of one AI model across all users over the queried period. */
export interface ModelUsage {
  /** Model id, e.g. "@cf/zai-org/glm-5.2" or "gpt-5.6-sol". */
  model: string;
  /** Total cost in USD across all users. */
  cost: number;
  /** Number of AI requests. */
  requests: number;
  /** Total input tokens. */
  tokensIn: number;
  /** Total output tokens. */
  tokensOut: number;
}

/** Deployment-wide usage aggregates for a period. */
export interface UsageSummary {
  /** Start of the UTC period actually covered, as an ISO 8601 date (inclusive). */
  from: string;
  /** End of the UTC period actually covered, as an ISO 8601 date (inclusive). */
  to: string;
  /** Total cost in USD across all users. */
  totalCost: number;
  /** Total number of AI requests. */
  totalRequests: number;
  /** Per-user aggregates, sorted by cost descending. */
  users: UserUsage[];
  /** Per-model aggregates across all users, sorted by cost descending. */
  models: ModelUsage[];
}

/** One usage session: a chat or gadget run, with its AI requests and cost. */
export interface UsageSession {
  /** User id (email) the session belongs to. */
  user: string;
  /** Chat id, when the session's requests came from a chat. */
  chatId?: string;
  /** Gadget id, when the session's requests came from a gadget or automation. */
  gadgetId?: string;
  /** ISO 8601 timestamp of the first request in the session. */
  firstActivity: string;
  /** ISO 8601 timestamp of the last request in the session. */
  lastActivity: string;
  /** Number of AI requests in the session. */
  requests: number;
  /** Total cost of the session in USD. */
  cost: number;
  /** Model ids used in the session, most-used first. */
  models: string[];
}

/**
 * Deployment-wide AI usage: sessions and cost for every user. Available to deployment
 * administrators only. All methods are read-only.
 *
 * Dates are UTC calendar dates in "YYYY-MM-DD" form; ranges are inclusive on both ends.
 * Cost figures come from the deployment's AI gateway and may lag live traffic by a few minutes.
 */
export interface DeploymentUsageSession {
  /**
   * Per-user and per-model cost/session aggregates for a date range. Defaults to the last
   * 30 days (both bounds optional).
   */
  getUsageSummary(options?: { from?: string; to?: string }): Promise<UsageSummary>;

  /**
   * Individual sessions, newest first, optionally filtered to one user (by email).
   * `limit` caps the result (default 100, max 500).
   */
  listSessions(options?: {
    user?: string;
    from?: string;
    to?: string;
    limit?: number;
  }): Promise<UsageSession[]>;
}
