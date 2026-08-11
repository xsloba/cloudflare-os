// Deployment Usage gatekeeper: read-only, administrator-only access to deployment-wide AI usage
// (sessions and cost per user), sourced from the deployment's AI Gateway logs.
//
// Access control happens at three layers:
//   1. Visibility — getSupportedResources({userId}) advertises nothing to non-admins, so the
//      connector never appears in their UI (the Workshop hides vendors with no resources).
//   2. Connect — the connect URL is served by this Worker, which must be deployed behind a
//      Cloudflare Access application. The handler verifies the Access JWT and refuses emails
//      not in USAGE_ADMINS, then bakes the verified email into the account.
//   3. Session — every startSession() re-checks the stored email against USAGE_ADMINS, so
//      removing an admin from the deployment config revokes their access on the next open.

import { DurableObject, RpcStub, RpcTarget, WorkerEntrypoint } from "cloudflare:workers";
import { createRemoteJWKSet, jwtVerify } from "jose";
import { skipRpcValidation, validateRpc } from "capnweb-validate";
import type {
  AccountDescription,
  ApprovalQueue,
  Gatekeeper,
  GatekeeperConnectCallback,
  GatekeeperConnectOptions,
  GatekeeperUser,
  GatekeeperUserVerifier,
  ResourceConfiguratorFrame,
  ResourceDescription,
  SupportedResource,
  VendorDescription,
} from "@gadgets/workshop-shared/gatekeeper";
import type { DeploymentUsageSession, UsageSession, UsageSummary } from "./types.js";
import {
  DayAggregate, GatewayLogsConfig, aggregateRows, dayRange, fetchDayRows, mergeAggregates,
  toSessions, toSummary, utcDayOf,
} from "./gateway-logs.js";
import TYPES_CODE from "./types.txt";
import USAGE_CONFIGURATOR_HTML from "./generated/usage-configurator-ui.txt";

type Env = Cloudflare.Env & {
  BASE_URL?: string;
  USAGE_ACCESS_ISS?: string;
  USAGE_ACCESS_AUD?: string;
  USAGE_ADMINS?: string;
  USAGE_GATEWAY_ACCOUNT_ID?: string;
  USAGE_GATEWAY_NAME?: string;
  USAGE_GATEWAY_API_TOKEN?: string;
};

const USAGE_ICON = {
  url:
    "data:image/svg+xml," +
    encodeURIComponent(
      "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 256 256' fill='none' " +
      "stroke='currentColor' stroke-width='20'><path d='M48 208V128M108 208V48M168 208v-96" +
      "M228 208V88'/></svg>",
    ),
};

const USAGE_RESOURCE_URL = "usage://deployment";

const USAGE_RESOURCE: SupportedResource = {
  urlPattern: USAGE_RESOURCE_URL,
  title: "Deployment usage",
  description: "AI sessions and cost for every user of this deployment (administrators only).",
  icon: USAGE_ICON,
};

const NONCE_BYTES = 32;
const NONCE_LIFETIME_MS = 10 * 60 * 1000;

// The widest getUsageSummary window, chosen to bound how many log pages one call can fetch.
const MAX_QUERY_DAYS = 92;
// How long an aggregate of the current (still-changing) UTC day is served before refetching.
const TODAY_TTL_MS = 5 * 60 * 1000;

function generateNonce(): string {
  return [...crypto.getRandomValues(new Uint8Array(NONCE_BYTES))]
      .map(b => b.toString(16).padStart(2, "0")).join("");
}

function constantTimeEqual(a: string, b: string): boolean {
  let encoder = new TextEncoder();
  let bufA = encoder.encode(a);
  let bufB = encoder.encode(b);
  if (bufA.byteLength !== bufB.byteLength) return false;
  return crypto.subtle.timingSafeEqual(bufA, bufB);
}

// The deployment's admin allowlist: USAGE_ADMINS is a comma-separated list of email addresses.
export function isUsageAdmin(env: Env, email: string | undefined): boolean {
  if (!email) return false;
  let admins = (env.USAGE_ADMINS ?? "").split(",").map(s => s.trim().toLowerCase())
      .filter(s => s !== "");
  return admins.includes(email.trim().toLowerCase());
}

function gatewayLogsConfig(env: Env): GatewayLogsConfig {
  if (!env.USAGE_GATEWAY_ACCOUNT_ID || !env.USAGE_GATEWAY_NAME || !env.USAGE_GATEWAY_API_TOKEN) {
    throw new Error(
        "The Deployment Usage gatekeeper requires USAGE_GATEWAY_ACCOUNT_ID, USAGE_GATEWAY_NAME " +
        "and USAGE_GATEWAY_API_TOKEN to be configured.");
  }
  return {
    accountId: env.USAGE_GATEWAY_ACCOUNT_ID,
    gateway: env.USAGE_GATEWAY_NAME,
    apiToken: env.USAGE_GATEWAY_API_TOKEN,
  };
}

function getBaseUrl(env: Env) {
  return (env.BASE_URL || "http://localhost:8787/gatekeeper/usage").replace(/\/+$/, "");
}

function getBasePath(env: Env) {
  const path = new URL(getBaseUrl(env)).pathname;
  return path === "/" ? "" : path;
}

const SELF_CLOSING_HTML = `<!DOCTYPE html>
<html lang="en">
  <body>
    <script type="text/javascript">window.close();</script>
    <p>Connection complete. You may close this tab and return to the Workshop.
  </body>
</html>`;

function errorHtml(message: string): Response {
  return new Response(
      `<!DOCTYPE html><html lang="en"><body><p>${message}</p></body></html>`,
      { status: 403, headers: { "Content-Type": "text/html; charset=utf-8" } });
}

// ---------------------------------------------------------------------------
// Cloudflare Access JWT verification. This Worker must be deployed behind an Access application
// covering its public hostname; Access then attaches a signed assertion to every request.

const remoteJwkSets = new Map<string, ReturnType<typeof createRemoteJWKSet>>();

async function verifyAccessEmail(request: Request, env: Env): Promise<string | null> {
  if (!env.USAGE_ACCESS_ISS || !env.USAGE_ACCESS_AUD) {
    throw new Error(
        "USAGE_ACCESS_ISS and USAGE_ACCESS_AUD must be configured so the connect flow can " +
        "verify the administrator's identity.");
  }
  let token = request.headers.get("cf-access-jwt-assertion");
  if (!token) return null;
  let jwks = remoteJwkSets.get(env.USAGE_ACCESS_ISS);
  if (!jwks) {
    jwks = createRemoteJWKSet(new URL(`${env.USAGE_ACCESS_ISS}/cdn-cgi/access/certs`));
    remoteJwkSets.set(env.USAGE_ACCESS_ISS, jwks);
  }
  try {
    let { payload } = await jwtVerify(token, jwks, {
      issuer: env.USAGE_ACCESS_ISS,
      audience: env.USAGE_ACCESS_AUD,
    });
    return typeof payload.email === "string" && payload.email !== "" ? payload.email : null;
  } catch {
    return null;
  }
}

// ---------------------------------------------------------------------------
// HTTP handler — completes the connect flow for an Access-authenticated administrator.

export default {
  async fetch(req: Request, env: Env, ctx: ExecutionContext) {
    let url = new URL(req.url);
    let basePath = getBasePath(env);
    if (!url.pathname.startsWith(basePath + "/") && url.pathname !== basePath) {
      return new Response("Not Found", { status: 404 });
    }
    let path = url.pathname.slice(basePath.length).slice(1).split("/");

    if (path.length === 2 && path[0].length === 64 && path[1].length === NONCE_BYTES * 2) {
      let stub = ctx.exports.UserAccount.get(ctx.exports.UserAccount.idFromString(path[0]));
      if (!await stub.verifyNonce(path[1])) {
        return errorHtml("This connection link has expired. Please start the connection again.");
      }

      let email = await verifyAccessEmail(req, env);
      if (!email) {
        return errorHtml(
            "Could not verify your identity. This connector must be reached through the " +
            "deployment's Cloudflare Access application.");
      }
      if (!isUsageAdmin(env, email)) {
        return errorHtml("Deployment usage data is available to deployment administrators only.");
      }

      await stub.completeConnection(email);
      return new Response(SELF_CLOSING_HTML, {
        headers: { "Content-Type": "text/html; charset=utf-8" },
      });
    }
    return new Response("Not Found", { status: 404 });
  },
};

// ---------------------------------------------------------------------------
// Vendor — top-level API exposed to the Workshop.

@validateRpc()
export class GatekeeperVendor extends WorkerEntrypoint<Env> {
  async describe(): Promise<VendorDescription> {
    return {
      displayName: "Deployment Usage",
      url: "https://developers.cloudflare.com/ai-gateway/",
      logo: USAGE_ICON,
      color: "#fff4e6",
      tagline: "AI sessions and cost for every user (administrators only)",
      description:
          "Read-only usage reporting for deployment administrators: which users are using AI, " +
          "in how many sessions, with which models, and at what cost.",
      providesAuth: false,
    };
  }

  async connectAccount(
      callback: Fetcher<GatekeeperConnectCallback>,
      _options?: GatekeeperConnectOptions): Promise<{ url: string }> {
    let userObjectId = this.ctx.exports.UserAccount.newUniqueId();
    let nonce = generateNonce();
    await this.ctx.exports.UserAccount.get(userObjectId).setCallback(callback, nonce);
    return { url: `${getBaseUrl(this.env)}/${userObjectId.toString()}/${nonce}` };
  }

  // RBAC-gated: only administrators see the resource, so the connector is hidden from everyone
  // else (the Workshop hides vendors that advertise no resources). Advisory only — enforcement
  // happens at connect (Access JWT) and again at every session start.
  async getSupportedResources(options?: { userId?: string }): Promise<SupportedResource[]> {
    return isUsageAdmin(this.env, options?.userId) ? [USAGE_RESOURCE] : [];
  }

  async getTypeScriptTypes(): Promise<string> {
    return TYPES_CODE;
  }
}

// ---------------------------------------------------------------------------
// UserAccount DO — stores the Access-verified administrator email.

@validateRpc()
export class UserAccount extends DurableObject<Env> {
  @skipRpcValidation()
  async setCallback(callback: Fetcher<GatekeeperConnectCallback>, nonce: string) {
    if (!this.ctx.storage.kv.get<string>("email")) {
      // Self-destruct if the connect flow is never completed.
      this.ctx.storage.setAlarm(Date.now() + 3600 * 1000);
    }
    this.ctx.storage.kv.put("callback", callback);
    this.ctx.storage.kv.put("nonce", { value: nonce, expiresAt: Date.now() + NONCE_LIFETIME_MS });
  }

  async verifyNonce(nonce: string): Promise<boolean> {
    let stored = this.ctx.storage.kv.get<{ value: string, expiresAt: number }>("nonce");
    if (!stored || Date.now() >= stored.expiresAt || !constantTimeEqual(stored.value, nonce)) {
      return false;
    }
    this.ctx.storage.kv.delete("nonce");
    return true;
  }

  async completeConnection(email: string): Promise<void> {
    let callback = this.ctx.storage.kv.get<Fetcher<GatekeeperConnectCallback>>("callback");
    if (!callback) {
      throw new Error("The connection timed out. Please start the connection again.");
    }

    this.ctx.storage.kv.put("email", email);
    try {
      await callback.complete(this.ctx.exports.UsageAccount({
        props: { userObjectId: this.ctx.id.toString() },
      }));
    } catch (err) {
      this.ctx.storage.kv.delete("email");
      throw err;
    }
    this.ctx.storage.kv.delete("callback");
    await this.ctx.storage.deleteAlarm();
  }

  async getEmail(): Promise<string> {
    let email = this.ctx.storage.kv.get<string>("email");
    if (!email) throw new Error("This connection was never completed. Please reconnect.");
    return email;
  }

  async alarm() {
    if (!this.ctx.storage.kv.get<string>("email")) {
      await this.ctx.storage.deleteAll();
    }
  }

  async revoke() {
    await this.ctx.storage.deleteAlarm();
    await this.ctx.storage.deleteAll();
  }
}

// ---------------------------------------------------------------------------
// UsageAccount — the connected administrator's account capability.

type UsageAccountProps = {
  userObjectId: string;
};

@validateRpc()
export class UsageAccount extends WorkerEntrypoint<Env, UsageAccountProps>
    implements GatekeeperUser {
  #account() {
    return this.ctx.exports.UserAccount.get(
        this.ctx.exports.UserAccount.idFromString(this.ctx.props.userObjectId));
  }

  async describe(): Promise<AccountDescription> {
    let email = await this.#account().getEmail();
    return {
      displayName: `Deployment usage (${email})`,
      avatar: USAGE_ICON,
    };
  }

  async getSupportedResources(): Promise<SupportedResource[]> {
    return [USAGE_RESOURCE];
  }

  async startResourceConfigurator(resourceUrlPattern: string): Promise<ResourceConfiguratorFrame> {
    if (resourceUrlPattern !== USAGE_RESOURCE.urlPattern) {
      throw new Error(`Unsupported resource configurator type: ${resourceUrlPattern}`);
    }
    return {
      iframeHtml: USAGE_CONFIGURATOR_HTML,
      ui: new RpcStub(new UsageConfiguratorUI()),
    };
  }

  @skipRpcValidation()
  async getGatekeeperClassFor(url: string): Promise<{
    class: DurableObjectClass<Gatekeeper<DeploymentUsageSession>>;
    resource: SupportedResource;
  }> {
    if (url !== USAGE_RESOURCE_URL) {
      throw new Error(`The Deployment Usage gatekeeper has one resource: ${USAGE_RESOURCE_URL}.`);
    }
    return {
      class: this.ctx.exports.UsageGatekeeperImpl({
        props: { userObjectId: this.ctx.props.userObjectId },
      }),
      resource: USAGE_RESOURCE,
    };
  }

  async ensureResources(_resourceUrlPatterns: string[]): Promise<{ url?: string }> {
    return {};
  }

  async revoke(): Promise<void> {
    await this.#account().revoke();
  }

  reconnect(): Promise<{ url: string }> {
    // The stored email never expires; admin status is re-checked live on every session start, so
    // there is nothing to refresh.
    throw new Error("This connection does not expire; disconnect and connect again instead.");
  }

  async getAuthenticatedEmail(): Promise<string | null> {
    return null;
  }

  @skipRpcValidation()
  async getVerifier(): Promise<Fetcher<GatekeeperUserVerifier>> {
    return this.ctx.exports.UsageVerifier({});
  }
}

// Strategy A (private-only): observers are never admitted, so the verifier is never consulted.
@validateRpc()
export class UsageVerifier extends WorkerEntrypoint<Env>
    implements GatekeeperUserVerifier {
  verify(): void {}
}

// ---------------------------------------------------------------------------
// Resource configurator — the resource is fixed, so the UI is confirmation-only.

@validateRpc()
export class UsageConfiguratorUI extends RpcTarget {
  async resourceUrl(): Promise<string> {
    return USAGE_RESOURCE_URL;
  }
}

// ---------------------------------------------------------------------------
// UsageGatekeeperImpl DO — per-binding instance; caches per-day aggregates.

type UsageGatekeeperImplProps = {
  userObjectId: string;
};

type CachedDay = { aggregate: DayAggregate, fetchedAt: number };

@validateRpc()
export class UsageGatekeeperImpl extends DurableObject<Env, UsageGatekeeperImplProps>
    implements Gatekeeper<DeploymentUsageSession> {

  async describe(): Promise<ResourceDescription> {
    return {
      url: USAGE_RESOURCE_URL,
      title: "Deployment usage",
      snippet: "AI sessions and cost for every user of this deployment.",
      suggestedBindingName: "DEPLOYMENT_USAGE",
      tsType: "DeploymentUsageSession",
    };
  }

  async getTypeScriptTypes(): Promise<string> {
    return TYPES_CODE;
  }

  async getAutoApprovableActions(): Promise<[]> {
    return [];
  }

  async startSession(approvalQueue: RpcStub<ApprovalQueue>): Promise<DeploymentUsageSession> {
    // Re-verify administrator status on every open, so removal from USAGE_ADMINS revokes access
    // without waiting for the account to be disconnected.
    let account = this.ctx.exports.UserAccount.get(
        this.ctx.exports.UserAccount.idFromString(this.ctx.props.userObjectId));
    let email = await account.getEmail();
    if (!isUsageAdmin(this.env, email)) {
      throw new Error("Deployment usage data is available to deployment administrators only.");
    }
    return new UsageSessionImpl(approvalQueue.dup(), this);
  }

  // Fetch (or serve from cache) the merged aggregate for an inclusive UTC day range. Whole past
  // days are immutable and cached forever; the current day is cached briefly.
  async getAggregate(from: string, to: string): Promise<DayAggregate> {
    let days = dayRange(from, to, MAX_QUERY_DAYS);
    let today = utcDayOf(new Date());
    let aggregates: DayAggregate[] = [];
    for (let day of days) {
      if (day > today) continue;  // The future has no logs.
      let key = `day:${day}`;
      let cached = this.ctx.storage.kv.get<CachedDay>(key);
      let fresh = cached !== undefined &&
          (day < today || Date.now() - cached.fetchedAt < TODAY_TTL_MS);
      if (cached !== undefined && fresh) {
        aggregates.push(cached.aggregate);
        continue;
      }
      let rows = await fetchDayRows(gatewayLogsConfig(this.env), day);
      let aggregate = aggregateRows(rows);
      this.ctx.storage.kv.put(key, { aggregate, fetchedAt: Date.now() } satisfies CachedDay);
      aggregates.push(aggregate);
    }
    return mergeAggregates(aggregates);
  }

  // Read-only gatekeeper: no actions are ever submitted, so these are never called.
  async applyAction(action: number): Promise<void> {
    throw new Error(`The Deployment Usage gatekeeper has no actions (${action}).`);
  }
  async rejectAction(_action: number): Promise<void> {}
  async revertAction(_action: number): Promise<void> {
    throw new Error("The Deployment Usage gatekeeper has no actions to revert.");
  }

  // Strategy A (private-only): deployment-wide usage data must not become observable to
  // collaborators through a shared gadget — each administrator connects their own account.
  async addObserver(_id: string, _user: Fetcher<GatekeeperUserVerifier>): Promise<void> {
    throw new Error(
        "Deployment usage data cannot be shared with collaborators. Each administrator must " +
        "open their own gadget with their own connection.");
  }
  async removeObserver(_id: string): Promise<void> {}
}

// ---------------------------------------------------------------------------
// SessionImpl — the RPC interface exposed to gadgets and agents.

function defaultRange(): { from: string, to: string } {
  let now = Date.now();
  return {
    from: utcDayOf(new Date(now - 29 * 24 * 60 * 60 * 1000)),
    to: utcDayOf(new Date(now)),
  };
}

function resolveRange(options?: { from?: string; to?: string }): { from: string, to: string } {
  let fallback = defaultRange();
  return { from: options?.from ?? fallback.from, to: options?.to ?? fallback.to };
}

@validateRpc()
export class UsageSessionImpl extends RpcTarget implements DeploymentUsageSession {
  readonly #approvalQueue: RpcStub<ApprovalQueue>;
  readonly #gatekeeper: UsageGatekeeperImpl;

  constructor(approvalQueue: RpcStub<ApprovalQueue>, gatekeeper: UsageGatekeeperImpl) {
    super();
    this.#approvalQueue = approvalQueue;
    this.#gatekeeper = gatekeeper;
  }

  async getUsageSummary(options?: { from?: string; to?: string }): Promise<UsageSummary> {
    let { from, to } = resolveRange(options);
    let aggregate = await this.#gatekeeper.getAggregate(from, to);
    await this.#approvalQueue.authorizeObservation({
      title: "Read deployment usage summary",
      description:
          `Read per-user and per-model AI usage aggregates for ${from}..${to} (UTC).`,
    });
    return toSummary(aggregate, from, to);
  }

  async listSessions(options?: {
    user?: string; from?: string; to?: string; limit?: number;
  }): Promise<UsageSession[]> {
    let { from, to } = resolveRange(options);
    let limit = Math.min(Math.max(1, options?.limit ?? 100), 500);
    let aggregate = await this.#gatekeeper.getAggregate(from, to);
    await this.#approvalQueue.authorizeObservation({
      title: "List usage sessions",
      description: `Read AI usage sessions for ${from}..${to} (UTC)` +
          (options?.user ? ` filtered to ${options.user}` : "") + ".",
    });
    return toSessions(aggregate, { user: options?.user, limit });
  }

  [Symbol.dispose](): void {
    this.#approvalQueue[Symbol.dispose]?.();
  }
}
