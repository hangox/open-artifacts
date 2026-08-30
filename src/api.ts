import type { Context } from "hono";
import { Hono } from "hono";
import type { Authorizer } from "./authorizer";
import { validateVisibility } from "./authorizer";
import type { CreateInput, VersionMeta } from "./domain";
import {
  MAX_COMMENT_BODY_BYTES,
  validateComment,
  validateCreate,
  validateUpdate,
} from "./domain";
import { broadcastVersionIfLive } from "./live-api";
import type { ArtifactRecord, ArtifactStore } from "./store";
import { D1R2Store } from "./store";
import {
  generateId,
  generateWriteToken,
  looksLikeChannelToken,
  sha256Hex,
  timingSafeEqual,
} from "./tokens";
import { generateNonce, userContentHeaders } from "./wrap";

export type Bindings = Env & {
  CREATE_TOKEN?: string;
  // POST /api/admin/gc 所需的 Bearer token。未设置或为空时始终锁定维护接口，
  // 不会回退为公开访问。
  ADMIN_TOKEN?: string;
  // POST /api/admin/gc 的存储容量上限，单位为字节。必须是非负安全整数的字符串；
  // 未设置或无效时接口以失败关闭方式拒绝执行。
  MAX_STORAGE_BYTES?: string;
  BRAND_URL?: string;
  BRAND_NAME?: string;
  BRAND_WORDMARK?: string;
  BRAND_TAGLINE?: string;
  BRAND_DESCRIPTION?: string;
  BRAND_LEAD?: string;
  BRAND_CHIP?: string;
  BRAND_STATUS_THEME?: "default" | "dark-console";
  PUBLIC_URL?: string;
  // "1" enables the opt-in web-font surface: the /fonts proxy plus a widened
  // font-src/style-src to the CDN allowlist. The sandbox stays opaque either
  // way — the opt-in never grants allow-same-origin (R1). Absent (or any other
  // value) keeps font-src data:-only.
  OPEN_ARTIFACTS_WEB_FONTS?: string;
  // Content cap in MiB. Unset keeps the deliberate 4 MiB free-tier default
  // (docs/architecture.md); a self-hoster on a paid plan raises it to publish
  // larger artifacts. See resolveMaxContentBytes for the parse/fallback rules.
  MAX_CONTENT_MIB?: string;
  // Live editing. Optional: a deploy opts in by binding a Durable
  // Object namespace named LIVE_DO whose class is the engine's LiveObject
  // (see src/live-do.ts). When unset, the /api/artifacts/:id/live* routes 404
  // and the host chrome renders no Live button — today's viewer is unchanged.
  LIVE_DO?: DurableObjectNamespace;
  // Handoff recording. Optional: a deploy opts in by setting this to "1". When
  // unset, the /api/artifacts/:id/handoffs* routes 404 and the host chrome
  // renders no Handoff button - the viewer is unchanged. No DO binding needed
  // (recording is host-side getUserMedia + R2 media/events); the flag only
  // gates the surface, mirroring OPEN_ARTIFACTS_WEB_FONTS.
  OPEN_ARTIFACTS_HANDOFF?: string;
};
export type AppContext = {
  Bindings: Bindings;
  Variables: { authorizer: Authorizer };
};

// The content cap defaults to 4 MiB — a deliberate free-tier envelope — and is
// overridable per instance via MAX_CONTENT_MIB. Unset, non-numeric, or <= 0
// falls back to 4 so the default stays byte-for-byte unchanged. Raising it far
// past a few MiB risks the Cloudflare Worker request-body / memory limit (the
// body is buffered by c.req.json() and held as a JS string), so a large cap is
// at the operator's own risk; keep this in lockstep with resolveMaxContentBytes
// in skills/using-open-artifacts/scripts/lib/limits.mjs.
export function resolveMaxContentBytes(env: Bindings): number {
  const raw = env.MAX_CONTENT_MIB ?? "";
  // Full-string digits only — parseInt("12abc") === 12 would silently raise
  // the cap contrary to the documented "non-numeric falls back" contract.
  if (!/^\d+$/.test(raw)) {
    return 4 * 1024 * 1024;
  }
  const mib = Number.parseInt(raw, 10);
  return (mib > 0 ? mib : 4) * 1024 * 1024;
}

// MAX_STORAGE_BYTES 采用失败关闭策略：自托管磁盘配额没有安全的默认值，
// 无效配置不能导致 GC 进行无界删除。允许配置为 0，以便运维明确清空 artifact
// 存储；该值的单位是字节。
export function resolveMaxStorageBytes(env: Bindings): number | null {
  const raw = env.MAX_STORAGE_BYTES ?? "";
  if (!/^\d+$/.test(raw)) return null;
  const bytes = Number(raw);
  return Number.isSafeInteger(bytes) && bytes >= 0 ? bytes : null;
}

// JSON escaping and encryption metadata inflate the body beyond the content
// cap; anything past this is rejected before parsing.
export const bodyCapFor = (maxContentBytes: number): number =>
  maxContentBytes * 1.5 + 16 * 1024;

export const storeFrom = (c: Context<AppContext>): ArtifactStore =>
  new D1R2Store(c.env.DB, c.env.CONTENT);

// Canonical origin for every generated link. A non-empty PUBLIC_URL pins
// links to the SaaS domain no matter which host the request arrived on (so
// workers.dev fallbacks and crawlers still get the canonical URL); unset (or
// empty, matching the CREATE_TOKEN convention) links follow the request
// origin so self-hosted instances stay on their own domain. The trailing
// slash is trimmed so PUBLIC_URL="https://x/" never yields "//a/".
export const baseUrl = (c: Context<AppContext>): string =>
  (c.env.PUBLIC_URL || new URL(c.req.url).origin).replace(/\/+$/, "");

export const artifactUrl = (c: Context<AppContext>, id: string): string =>
  `${baseUrl(c)}/a/${id}`;

export const ogImageUrl = (c: Context<AppContext>, id: string): string =>
  `${baseUrl(c)}/og/${id}`;

// WebSocket URL for the live channel on a given artifact. baseUrl is an
// absolute http(s) origin; swap the scheme to ws/wss for the WS upgrade route.
export const liveWsUrl = (c: Context<AppContext>, id: string): string =>
  `${baseUrl(c).replace(/^http/, "ws")}/api/artifacts/${id}/live`;

// Handoff recording is opt-in per deploy (OPEN_ARTIFACTS_HANDOFF=1). The host
// chrome inlines these same-origin URLs so the play UI can fetch media/events
// (connect-src 'self') and object-URL them into a <video> overlay.
export const handoffEnabled = (c: Context<AppContext>): boolean =>
  c.env.OPEN_ARTIFACTS_HANDOFF === "1";

function bearerToken(c: Context<AppContext>): string | null {
  const header = c.req.header("authorization");
  const match = header?.match(/^Bearer\s+(.+)$/i);
  return match ? match[1] : null;
}

export { bearerToken };

async function authorizeAdmin(c: Context<AppContext>): Promise<boolean> {
  const configured = c.env.ADMIN_TOKEN;
  if (typeof configured !== "string" || configured === "") return false;
  const token = bearerToken(c);
  // 比较前先对两边都做哈希，避免明文 secret 进入时序敏感的比较；缺少凭据时也
  // 走与错误凭据相同的恒定时间比较路径。
  return timingSafeEqual(
    await sha256Hex(token ?? ""),
    await sha256Hex(configured),
  );
}

type AuthResult =
  | { ok: true; record: ArtifactRecord }
  | { ok: false; response: Response };

export async function authorizeWrite(
  c: Context<AppContext>,
  store: ArtifactStore,
  id: string,
): Promise<AuthResult> {
  const record = await store.get(id);
  if (record === null) {
    return {
      ok: false,
      response: c.json({ error: "artifact not found" }, 404),
    };
  }

  const token = bearerToken(c);
  if (token !== null) {
    const tokenHash = await sha256Hex(token);
    const authorized = looksLikeChannelToken(token)
      ? record.channelHash !== null &&
        timingSafeEqual(tokenHash, record.channelHash)
      : timingSafeEqual(tokenHash, record.tokenHash);
    if (authorized) {
      return { ok: true, record };
    }
  }

  if (await c.get("authorizer").authorizeWrite(c, record)) {
    return { ok: true, record };
  }

  if (token === null) {
    return {
      ok: false,
      response: c.json({ error: "missing bearer write token" }, 401),
    };
  }
  return {
    ok: false,
    response: c.json({ error: "invalid write token" }, 403),
  };
}

export function parseVersionParam(
  raw: string | undefined,
  currentVersion: number,
): number | { error: string; status: 400 | 404 } {
  if (raw === undefined) return currentVersion;
  if (!/^\d+$/.test(raw))
    return { error: "v must be a positive integer", status: 400 };
  const version = Number(raw);
  if (version < 1 || version > currentVersion) {
    return { error: "version not found", status: 404 };
  }
  return version;
}

export const api = new Hono<AppContext>();

// Publish a create payload as a new version of the channel's artifact. A
// channel publish carries no baseVersion, so losing the compare-and-swap only
// means another publish landed first — retry on a fresh snapshot instead of
// surfacing a 409 the caller can do nothing about.
async function publishToChannel(
  c: Context<AppContext>,
  store: ArtifactStore,
  record: ArtifactRecord,
  input: CreateInput,
  channel: string,
): Promise<Response> {
  let snapshot: ArtifactRecord | null = record;
  let currentVersion = record.currentVersion;
  for (let attempt = 0; attempt < 3 && snapshot !== null; attempt += 1) {
    const result = await store.update(snapshot, {
      content: input.content,
      format: input.format,
      title: input.title,
      description: input.description,
      favicon: input.favicon,
      label: input.label,
      encrypted: input.encrypted,
      baseVersion: null,
      force: false,
    });
    if (typeof result === "number") {
      await broadcastVersionIfLive(c, snapshot.id, result);
      return c.json({
        id: snapshot.id,
        url: artifactUrl(c, snapshot.id),
        version: result,
        channel,
      });
    }
    currentVersion = result.currentVersion;
    snapshot = await store.get(snapshot.id);
  }
  return c.json({ error: "version conflict", currentVersion }, 409);
}

const isChannelBindingConflict = (error: unknown): boolean =>
  error instanceof Error &&
  error.message.includes("UNIQUE constraint failed") &&
  error.message.includes("channel_hash");

// 供服务器 crontab 调用的维护接口。使用配置的精确上限，而不是任意的 90% 目标，
// 避免删除额外用户数据；下一次调用会在再次超过上限前保持无操作。
api.post("/admin/gc", async (c) => {
  // ADMIN_TOKEN 缺失时明确保持锁定，绝不能变成公开接口。
  if (typeof c.env.ADMIN_TOKEN !== "string" || c.env.ADMIN_TOKEN === "") {
    return c.json({ error: "admin endpoint is not configured" }, 403);
  }
  const token = bearerToken(c);
  if (!(await authorizeAdmin(c))) {
    return c.json(
      {
        error:
          token === null ? "missing bearer admin token" : "invalid admin token",
      },
      token === null ? 401 : 403,
    );
  }

  const maxStorageBytes = resolveMaxStorageBytes(c.env);
  if (maxStorageBytes === null) {
    return c.json(
      {
        error:
          "MAX_STORAGE_BYTES must be a non-negative safe integer number of bytes",
      },
      500,
    );
  }

  const store = storeFrom(c);
  const artifacts = await store.listArtifactStorage();
  const usedBytesBefore = artifacts.reduce(
    (total, artifact) => total + artifact.totalSize,
    0,
  );
  let usedBytesAfter = usedBytesBefore;
  const deletedArtifactIds: string[] = [];

  if (usedBytesBefore > maxStorageBytes) {
    for (const artifact of artifacts) {
      if (usedBytesAfter <= maxStorageBytes) break;
      // 复用规范删除路径，确保该 artifact 的 versions、comments、handoffs 以及
      // R2 中分页列出的全部内容一起删除。
      await store.delete(artifact.id);
      deletedArtifactIds.push(artifact.id);
      usedBytesAfter -= artifact.totalSize;
    }
  }

  return c.json({
    usedBytesBefore,
    usedBytesAfter,
    maxStorageBytes,
    triggered: usedBytesBefore > maxStorageBytes,
    deletedArtifactIds,
  });
});

api.post("/artifacts", async (c) => {
  const maxContentBytes = resolveMaxContentBytes(c.env);
  const declaredLength = Number(c.req.header("content-length") ?? "0");
  if (declaredLength > bodyCapFor(maxContentBytes)) {
    return c.json({ error: "request body too large" }, 413);
  }

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ error: "request body must be JSON" }, 400);
  }

  // Authorize after the body is buffered so SaaS authorizers can read
  // visibility/orgId from the same JSON the engine validates (Hono caches
  // c.req.json()). defaultAuthorizer still stamps public/anonymous ownership.
  const grant = await c.get("authorizer").authorizeCreate(c);
  if (!grant) return c.json({ error: "unauthorized" }, 401);

  const parsed = validateCreate(body, maxContentBytes);
  if (!parsed.ok) return c.json({ error: parsed.error }, parsed.status);

  const store = storeFrom(c);

  // Channel binding: a POST carrying a channel token (ch_) targets the
  // artifact already bound to that channel — creating a new version at the
  // same URL instead of minting a new artifact. First use of a channel
  // creates the artifact and binds the channel to it, so every future POST
  // with the same channel lands on the same link.
  const channelRaw = typeof body.channel === "string" ? body.channel : null;
  if (channelRaw !== null && !looksLikeChannelToken(channelRaw)) {
    return c.json({ error: "channel must be a channel token (ch_...)" }, 400);
  }

  const channelHash = channelRaw !== null ? await sha256Hex(channelRaw) : null;
  if (channelRaw !== null && channelHash !== null) {
    const existing = await store.findByChannel(channelHash);
    if (existing !== null) {
      return publishToChannel(c, store, existing, parsed.value, channelRaw);
    }
  }

  const id = generateId();
  const writeToken = generateWriteToken();
  try {
    await store.create(
      id,
      await sha256Hex(writeToken),
      parsed.value,
      channelHash,
      grant,
    );
  } catch (error) {
    // Two concurrent first publishes to one channel: the unique index lets
    // exactly one create win; the loser lands here and becomes a version
    // update on the winner's artifact, keeping the channel's URL stable.
    if (channelRaw === null || channelHash === null) throw error;
    if (!isChannelBindingConflict(error)) throw error;
    const winner = await store.findByChannel(channelHash);
    if (winner === null) throw error;
    return publishToChannel(c, store, winner, parsed.value, channelRaw);
  }

  // Indirect access so TS does not statically resolve the check to always-true
  // when the deploy's generated Env types LIVE_DO as required (coda0). The
  // engine itself declares LIVE_DO optional — a self-host without the binding
  // reports liveSupported false and the CLI skips the watcher tip.
  const liveSupported = Boolean(
    (c.env as unknown as Record<string, unknown>).LIVE_DO,
  );
  return c.json(
    {
      id,
      url: artifactUrl(c, id),
      writeToken,
      version: 1,
      liveSupported,
      ...(channelRaw ? { channel: channelRaw } : {}),
    },
    201,
  );
});

api.put("/artifacts/:id", async (c) => {
  const store = storeFrom(c);
  const auth = await authorizeWrite(c, store, c.req.param("id"));
  if (!auth.ok) return auth.response;

  // Same pre-parse body cap as POST: reject an oversized declared body before
  // c.req.json() buffers it into worker memory. PUT lacked this guard, so an
  // over-cap update was only caught after the whole body was parsed.
  const maxContentBytes = resolveMaxContentBytes(c.env);
  const declaredLength = Number(c.req.header("content-length") ?? "0");
  if (declaredLength > bodyCapFor(maxContentBytes)) {
    return c.json({ error: "request body too large" }, 413);
  }

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ error: "request body must be JSON" }, 400);
  }

  const parsed = validateUpdate(body, maxContentBytes);
  if (!parsed.ok) return c.json({ error: parsed.error }, parsed.status);

  const { baseVersion, force } = parsed.value;
  if (
    baseVersion !== null &&
    baseVersion !== auth.record.currentVersion &&
    !force
  ) {
    return c.json(
      {
        error: `baseVersion ${baseVersion} does not match current version ${auth.record.currentVersion}`,
        currentVersion: auth.record.currentVersion,
      },
      409,
    );
  }

  const result = await store.update(auth.record, parsed.value);
  if (typeof result !== "number") {
    return c.json(
      {
        error: `version conflict: artifact is at version ${result.currentVersion}`,
        currentVersion: result.currentVersion,
      },
      409,
    );
  }
  // Tell staying viewers a new version landed so the host reloads in place.
  // No-ops when the deploy did not bind LIVE_DO.
  await broadcastVersionIfLive(c, auth.record.id, result);
  return c.json({
    id: auth.record.id,
    url: artifactUrl(c, auth.record.id),
    version: result,
  });
});

api.delete("/artifacts/:id", async (c) => {
  const store = storeFrom(c);
  const auth = await authorizeWrite(c, store, c.req.param("id"));
  if (!auth.ok) return auth.response;
  await store.delete(auth.record.id);
  return c.json({ ok: true });
});

api.get("/artifacts/:id", async (c) => {
  const store = storeFrom(c);
  const record = await store.get(c.req.param("id"));
  if (record === null) return c.json({ error: "artifact not found" }, 404);
  if (!(await c.get("authorizer").authorizeView(c, record))) {
    return c.json({ error: "artifact not found" }, 404);
  }
  const versions = await store.listVersions(record.id);
  const visibleVersions: VersionMeta[] = [];
  for (const version of versions) {
    if (await c.get("authorizer").authorizeView(c, record, version.version)) {
      visibleVersions.push(version);
    }
  }
  return c.json({
    id: record.id,
    url: artifactUrl(c, record.id),
    title: record.title,
    description: record.description,
    favicon: record.favicon,
    format: record.format,
    encrypted: record.encrypted,
    version: record.currentVersion,
    versions: visibleVersions,
    createdAt: record.createdAt,
    updatedAt: record.updatedAt,
  });
});

api.get("/artifacts/:id/raw", async (c) => {
  const store = storeFrom(c);
  const record = await store.get(c.req.param("id"));
  if (record === null) return c.json({ error: "artifact not found" }, 404);

  const version = parseVersionParam(c.req.query("v"), record.currentVersion);
  if (typeof version !== "number") {
    return c.json({ error: version.error }, version.status);
  }
  if (!(await c.get("authorizer").authorizeView(c, record, version))) {
    return c.json({ error: "artifact not found" }, 404);
  }

  const content = await store.getContent(record.id, version);
  if (content === null) return c.json({ error: "content not found" }, 404);

  if (content.encrypted !== null) {
    const headers = userContentHeaders({
      sandbox: true,
      contentType: "application/json",
      nonce: generateNonce(),
    });
    return new Response(
      JSON.stringify({
        alg: "AES-GCM",
        kdf: "PBKDF2-SHA256",
        iterations: content.encrypted.iterations,
        salt: content.encrypted.salt,
        iv: content.encrypted.iv,
        ciphertext: content.body,
      }),
      { headers },
    );
  }

  const headers = userContentHeaders({
    sandbox: true,
    contentType: "text/plain; charset=utf-8",
    nonce: generateNonce(),
  });
  return new Response(content.body, { headers });
});

// Comment thread on an artifact. The thread lives in the surrounding chrome
// (not the sandboxed iframe body), so the host page POSTs and renders the list.
// Phase 1: posting is open (not token-gated) and reads are open — the issue
// lists the auth model as an open question. A persisted comment reaches every
// future viewer because the host fetches the thread on page load. Live
// (no-reload) fan-out across concurrent viewers is Phase 2 (Durable Object).
// Headroom over the body cap for everything else a comment may legitimately
// carry: an anchor (≤2 KiB), an author (≤200 chars), and JSON braces/escaping.
// Too tight and a comment validateComment would accept is 413'd before it is
// read; validateComment stays the authoritative per-field gate.
const COMMENT_BODY_BYTES = MAX_COMMENT_BODY_BYTES + 4 * 1024;

api.get("/artifacts/:id/comments", async (c) => {
  const store = storeFrom(c);
  const record = await store.get(c.req.param("id"));
  if (record === null) return c.json({ error: "artifact not found" }, 404);
  if (!(await c.get("authorizer").authorizeView(c, record))) {
    return c.json({ error: "artifact not found" }, 404);
  }
  const comments = await store.listComments(record.id);
  return c.json({ comments });
});

api.post("/artifacts/:id/comments", async (c) => {
  const store = storeFrom(c);
  const record = await store.get(c.req.param("id"));
  if (record === null) return c.json({ error: "artifact not found" }, 404);
  if (!(await c.get("authorizer").authorizeView(c, record))) {
    return c.json({ error: "artifact not found" }, 404);
  }

  const declaredLength = Number(c.req.header("content-length") ?? "0");
  if (declaredLength > COMMENT_BODY_BYTES) {
    return c.json({ error: "request body too large" }, 413);
  }

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ error: "request body must be JSON" }, 400);
  }

  const parsed = validateComment(body);
  if (!parsed.ok) return c.json({ error: parsed.error }, parsed.status);

  // Stamp/clamp anchorVersion to the artifact's version space so a client
  // cannot forge a future version that hides markers for every real viewer
  // (anchorVersion > viewedVersion filters them out). Keep an in-range claim;
  // otherwise stamp currentVersion.
  //
  // The raw body is consulted because validateAnchor fills a missing
  // anchorVersion with a placeholder the domain layer cannot know is right —
  // it has no artifact. Trusting that value would record every version-less
  // API post as v1: a false drift tag, and a marker on versions where the
  // comment never existed.
  //
  // This runs before the encryption guard below because the guard must check
  // the version the anchor actually lands on — the stamped value, not the raw
  // claim — so a forged out-of-range anchorVersion cannot route around it.
  let input = parsed.value;
  if (input.anchor) {
    const rawAnchor = body.anchor as Record<string, unknown> | null | undefined;
    const claimed = input.anchor.anchorVersion;
    const stamped =
      typeof rawAnchor?.anchorVersion === "number" &&
      claimed <= record.currentVersion
        ? claimed
        : record.currentVersion;
    input = {
      ...input,
      anchor: { ...input.anchor, anchorVersion: stamped },
    };
  }

  // A text anchor stores a verbatim quote of the artifact body. On an encrypted
  // version the server never holds plaintext, so accepting one would copy
  // plaintext into D1 and break the zero-knowledge guarantee. Point anchors
  // (world coordinates) and unanchored comments leak nothing and are allowed.
  //
  // Check the ANCHORED version's own encryption state, not record.encrypted:
  // that flag is artifact-level (the current version), so on a mixed-encryption
  // artifact — v1 encrypted, v2 plaintext — it reads plaintext and would wave
  // through a quote of v1's still-secret body. getContentMeta reads the R2
  // object's per-version flag, the authoritative source /raw and the viewer
  // already use. A missing version fails closed (treated as encrypted).
  if (input.anchor?.mode === "text") {
    const meta = await store.getContentMeta(
      record.id,
      input.anchor.anchorVersion,
    );
    if (meta === null || meta.encrypted) {
      return c.json(
        { error: "text anchors are not allowed on encrypted artifacts" },
        400,
      );
    }
  }

  // Per-comment delete token, mirroring the artifact write-token idiom: only the
  // SHA-256 hash is stored; the plaintext is returned once so the poster can
  // delete their own comment later.
  const deleteToken = generateWriteToken();
  const comment = await store.addComment(
    record.id,
    input,
    await sha256Hex(deleteToken),
  );
  return c.json({ ...comment, deleteToken }, 201);
});

// Authorizes a mutation of an existing comment: the comment's own delete token
// (the author, from this browser) or the artifact's write/channel token (owner
// moderation). Legacy Phase-1 rows have a null delete-token hash and so are
// owner-only. Shared by PATCH and DELETE — resolving a comment hides it from
// the drawer's default view, so it is gated exactly like removing it.
async function authorizeCommentMutation(
  c: Context<AppContext>,
  store: ArtifactStore,
  artifactId: string,
  deleteTokenHash: string | null,
): Promise<{ ok: true } | { ok: false; status: 401 | 403; error: string }> {
  const token = bearerToken(c);
  if (token === null) {
    return { ok: false, status: 401, error: "missing bearer token" };
  }
  const tokenHash = await sha256Hex(token);
  const authorMatch =
    deleteTokenHash !== null && timingSafeEqual(tokenHash, deleteTokenHash);
  if (authorMatch) return { ok: true };
  if ((await authorizeWrite(c, store, artifactId)).ok) return { ok: true };
  return { ok: false, status: 403, error: "not authorized for this comment" };
}

// Mark done / undone. Not open like create: done removes a comment from the
// drawer's default "open" view, so an unauthenticated toggle would let any
// passer-by silently suppress a whole thread.
api.patch("/artifacts/:id/comments/:commentId", async (c) => {
  const store = storeFrom(c);
  const id = c.req.param("id");
  const commentId = c.req.param("commentId");

  const comment = await store.getComment(commentId);
  if (comment === null || comment.artifactId !== id) {
    return c.json({ error: "comment not found" }, 404);
  }

  const auth = await authorizeCommentMutation(
    c,
    store,
    id,
    comment.deleteTokenHash,
  );
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ error: "request body must be JSON" }, 400);
  }
  if (typeof body.done !== "boolean") {
    return c.json({ error: "done must be a boolean" }, 400);
  }

  const ok = await store.setCommentDone(commentId, body.done);
  if (!ok) return c.json({ error: "comment not found" }, 404);
  return c.json({ ok: true, done: body.done });
});

api.delete("/artifacts/:id/comments/:commentId", async (c) => {
  const store = storeFrom(c);
  const id = c.req.param("id");
  const commentId = c.req.param("commentId");

  const comment = await store.getComment(commentId);
  if (comment === null || comment.artifactId !== id) {
    return c.json({ error: "comment not found" }, 404);
  }

  const auth = await authorizeCommentMutation(
    c,
    store,
    id,
    comment.deleteTokenHash,
  );
  if (!auth.ok) return c.json({ error: auth.error }, auth.status);

  await store.deleteComment(commentId);
  return c.json({ ok: true });
});

api.patch("/artifacts/:id", async (c) => {
  const store = storeFrom(c);
  const id = c.req.param("id");
  const record = await store.get(id);
  // Collapse missing and not-manageable to the same 404 so PATCH cannot
  // probe private artifact existence (matches GET/raw/frame unauthorized).
  if (record === null || !(await c.get("authorizer").canManage(c, record))) {
    return c.json({ error: "artifact not found" }, 404);
  }

  let body: Record<string, unknown>;
  try {
    body = await c.req.json<Record<string, unknown>>();
  } catch {
    return c.json({ error: "request body must be JSON" }, 400);
  }

  const v = validateVisibility(body.visibility);
  if (!v) {
    return c.json({ error: "visibility must be private, org, or public" }, 400);
  }

  await store.updateVisibility(id, v);
  return c.json({ id, visibility: v });
});
