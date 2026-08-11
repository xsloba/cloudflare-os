import { describe, expect, it, vi } from "vitest";
import {
  UNATTRIBUTED_USER, aggregateRows, dayRange, fetchDayRows, mergeAggregates, parseLogRow,
  toSessions, toSummary, type LogRow,
} from "../src/gateway-logs.js";

function row(overrides: Partial<LogRow> = {}): LogRow {
  return {
    createdAt: "2026-08-01T10:00:00Z",
    model: "@cf/zai-org/glm-5.2",
    cost: 0.01,
    tokensIn: 100,
    tokensOut: 50,
    user: "alice@example.com",
    chatId: "1",
    ...overrides,
  };
}

describe("parseLogRow", () => {
  it("reads user, chat and gadget attribution from string metadata", () => {
    let parsed = parseLogRow({
      created_at: "2026-08-01T10:00:00Z",
      model: "gpt-5.6-sol",
      cost: 0.25,
      tokens_in: 10,
      tokens_out: 20,
      // The Workshop numbers chats, so chatId can arrive as a JSON number.
      metadata: JSON.stringify({ user: "alice@example.com", chatId: 7 }),
    });

    expect(parsed).toEqual({
      createdAt: "2026-08-01T10:00:00Z",
      model: "gpt-5.6-sol",
      cost: 0.25,
      tokensIn: 10,
      tokensOut: 20,
      user: "alice@example.com",
      chatId: "7",
    });
  });

  it("degrades malformed metadata and negative cost to safe defaults", () => {
    let parsed = parseLogRow({
      created_at: "2026-08-01T10:00:00Z",
      metadata: "{not json",
      cost: -5,
    });

    expect(parsed).toMatchObject({
      user: UNATTRIBUTED_USER,
      model: "(unknown)",
      cost: 0,
    });
    expect(parsed!.chatId).toBeUndefined();
  });

  it("rejects rows without a timestamp", () => {
    expect(parseLogRow({ model: "x" })).toBeNull();
    expect(parseLogRow("nonsense")).toBeNull();
  });
});

describe("aggregation", () => {
  let rows: LogRow[] = [
    row({ createdAt: "2026-08-01T10:00:00Z", cost: 0.01 }),
    row({ createdAt: "2026-08-01T10:05:00Z", cost: 0.02, model: "gpt-5.6-sol" }),
    row({ createdAt: "2026-08-01T11:00:00Z", cost: 0.10, user: "bob@example.com", chatId: "9" }),
    row({ createdAt: "2026-08-01T12:00:00Z", cost: 0.05, user: "bob@example.com",
          chatId: undefined, gadgetId: "g1" }),
  ];

  it("aggregates per user, per model, and per session", () => {
    let summary = toSummary(aggregateRows(rows), "2026-08-01", "2026-08-01");

    expect(summary.totalRequests).toBe(4);
    expect(summary.totalCost).toBeCloseTo(0.18);

    // Sorted by cost descending: bob (0.15) before alice (0.03).
    expect(summary.users.map(u => u.user))
        .toEqual(["bob@example.com", "alice@example.com"]);
    expect(summary.users[0]).toMatchObject({ sessions: 2, requests: 2 });
    expect(summary.users[1].costByModel).toEqual({
      "@cf/zai-org/glm-5.2": 0.01, "gpt-5.6-sol": 0.02,
    });

    expect(summary.models.map(m => m.model))
        .toEqual(["@cf/zai-org/glm-5.2", "gpt-5.6-sol"]);
    expect(summary.models[0]).toMatchObject({ requests: 3 });
    expect(summary.models[0].cost).toBeCloseTo(0.16);
  });

  it("lists sessions newest-last-activity first with per-user filtering", () => {
    let sessions = toSessions(aggregateRows(rows), {});
    expect(sessions.map(s => s.chatId ?? s.gadgetId)).toEqual(["g1", "9", "1"]);
    expect(sessions[2]).toMatchObject({
      user: "alice@example.com",
      firstActivity: "2026-08-01T10:00:00Z",
      lastActivity: "2026-08-01T10:05:00Z",
      requests: 2,
    });
    // Alice's session used GLM and GPT once each; order between equals is stable but both appear.
    expect(sessions[2].models).toHaveLength(2);

    expect(toSessions(aggregateRows(rows), { user: "bob@example.com" })).toHaveLength(2);
    expect(toSessions(aggregateRows(rows), { limit: 1 })).toHaveLength(1);
  });

  it("merges sessions that span days without double-counting users", () => {
    let day1 = aggregateRows([row({ createdAt: "2026-08-01T23:50:00Z" })]);
    let day2 = aggregateRows([row({ createdAt: "2026-08-02T00:10:00Z", cost: 0.04 })]);

    let summary = toSummary(mergeAggregates([day1, day2]), "2026-08-01", "2026-08-02");
    expect(summary.users).toHaveLength(1);
    // One chat across midnight stays one session.
    expect(summary.users[0]).toMatchObject({ sessions: 1, requests: 2 });
    expect(summary.users[0].cost).toBeCloseTo(0.05);

    let sessions = toSessions(mergeAggregates([day1, day2]), {});
    expect(sessions).toHaveLength(1);
    expect(sessions[0]).toMatchObject({
      firstActivity: "2026-08-01T23:50:00Z",
      lastActivity: "2026-08-02T00:10:00Z",
    });
  });
});

describe("dayRange", () => {
  it("lists inclusive UTC days", () => {
    expect(dayRange("2026-07-30", "2026-08-01", 92))
        .toEqual(["2026-07-30", "2026-07-31", "2026-08-01"]);
  });

  it("rejects malformed, inverted, and oversized ranges", () => {
    expect(() => dayRange("yesterday", "2026-08-01", 92)).toThrow(/YYYY-MM-DD/);
    expect(() => dayRange("2026-08-02", "2026-08-01", 92)).toThrow(/Invalid date range/);
    expect(() => dayRange("2026-01-01", "2026-12-31", 92)).toThrow(/at most 92 days/);
  });
});

describe("fetchDayRows", () => {
  it("pages until a short page and passes the day window and auth", async () => {
    let pages = [
      Array.from({ length: 50 }, (_, i) => ({
        created_at: `2026-08-01T10:00:${String(i % 60).padStart(2, "0")}Z`,
        model: "m", cost: 0.01, tokens_in: 1, tokens_out: 1,
        metadata: JSON.stringify({ user: "alice@example.com", chatId: 1 }),
      })),
      [{
        created_at: "2026-08-01T11:00:00Z",
        model: "m", cost: 0.01, tokens_in: 1, tokens_out: 1,
        metadata: JSON.stringify({ user: "alice@example.com", chatId: 1 }),
      }],
    ];
    let fetchMock = vi.fn(async (url: string | URL | Request, init?: RequestInit) => {
      void init;
      let parsed = new URL(String(url));
      expect(parsed.pathname).toBe(
          "/client/v4/accounts/acct/ai-gateway/gateways/gw/logs");
      expect(parsed.searchParams.get("start_date")).toBe("2026-08-01T00:00:00Z");
      return Response.json({ success: true, result: pages[Number(parsed.searchParams.get("page")) - 1] });
    });

    let rows = await fetchDayRows(
        { accountId: "acct", gateway: "gw", apiToken: "token" }, "2026-08-01",
        fetchMock as unknown as typeof fetch);

    expect(rows).toHaveLength(51);
    expect(fetchMock).toHaveBeenCalledTimes(2);
    let init = fetchMock.mock.calls[0][1]!;
    expect((init.headers as Record<string, string>).Authorization).toBe("Bearer token");
  });

  it("surfaces API failures", async () => {
    let fetchMock = vi.fn(async () => new Response("nope", { status: 403 }));
    await expect(fetchDayRows(
        { accountId: "acct", gateway: "gw", apiToken: "token" }, "2026-08-01",
        fetchMock as unknown as typeof fetch)).rejects.toThrow(/status 403/);
  });
});
