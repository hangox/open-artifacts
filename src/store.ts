import type { OwnershipGrant, Visibility } from "./authorizer";
import type {
  Anchor,
  ArtifactFormat,
  ArtifactMeta,
  CommentInput,
  CommentMeta,
  CreateInput,
  EncryptionParams,
  HandoffCreateInput,
  HandoffMeta,
  UpdateInput,
  VersionMeta,
} from "./domain";
import { contentByteLength } from "./domain";
import { generateId } from "./tokens";

export interface ArtifactRecord extends ArtifactMeta {
  tokenHash: string;
  channelHash: string | null;
  ownerId: string;
  orgId: string | null;
  visibility: Visibility;
}

export interface ArtifactStorage {
  id: string;
  createdAt: string;
  totalSize: number;
}

export interface StoredContent {
  body: string;
  encrypted: EncryptionParams | null;
}

export interface ArtifactStore {
  create(
    id: string,
    tokenHash: string,
    input: CreateInput,
    channelHash: string | null,
    ownership?: OwnershipGrant | null,
  ): Promise<ArtifactRecord>;
  get(id: string): Promise<ArtifactRecord | null>;
  findByChannel(channelHash: string): Promise<ArtifactRecord | null>;
  listArtifactStorage(): Promise<ArtifactStorage[]>;
  listVersions(id: string): Promise<VersionMeta[]>;
  getContent(id: string, version: number): Promise<StoredContent | null>;
  // Authoritative per-version encrypted flag without reading the ≤4 MiB body.
  // The versions-table flag can be stale on legacy mixed-encryption artifacts
  // (the ensureSchema backfill stamps it from the artifact's current state),
  // so the host route reads R2 object metadata instead.
  getContentMeta(
    id: string,
    version: number,
  ): Promise<{ encrypted: boolean } | null>;
  update(
    record: ArtifactRecord,
    input: UpdateInput,
  ): Promise<number | { conflict: true; currentVersion: number }>;
  replaceCurrent(
    record: ArtifactRecord,
    input: UpdateInput,
  ): Promise<number | { conflict: true; currentVersion: number }>;
  delete(id: string): Promise<void>;
  updateVisibility(id: string, visibility: Visibility): Promise<void>;
  listComments(artifactId: string): Promise<CommentMeta[]>;
  addComment(
    artifactId: string,
    input: CommentInput,
    deleteTokenHash?: string | null,
  ): Promise<CommentMeta>;
  getComment(
    commentId: string,
  ): Promise<{ artifactId: string; deleteTokenHash: string | null } | null>;
  setCommentDone(commentId: string, done: boolean): Promise<boolean>;
  deleteComment(commentId: string): Promise<void>;

  // Handoff recordings (webcam+mic + interaction events) for an artifact. Media
  // + events live in R2 under handoff/<artifactId>/<handoffId>/{media,events};
  // only metadata is in D1. createHandoff owns the R2 puts + D1 insert together
  // so an orphaned R2 object never survives a failed D1 write. deleteHandoff
  // returns false if the row does not exist (the route 404s).
  listHandoffs(artifactId: string): Promise<HandoffMeta[]>;
  createHandoff(
    artifactId: string,
    input: HandoffCreateInput,
    media: { body: ReadableStream | string | ArrayBuffer | Blob; size: number },
    events: { json: string; size: number },
    deleteTokenHash: string | null,
  ): Promise<HandoffMeta>;
  getHandoff(
    artifactId: string,
    handoffId: string,
  ): Promise<HandoffMeta | null>;
  getHandoffAuth(
    artifactId: string,
    handoffId: string,
  ): Promise<{ deleteTokenHash: string | null } | null>;
  getHandoffMedia(
    artifactId: string,
    handoffId: string,
  ): Promise<{ body: ReadableStream; mediaType: string } | null>;
  getHandoffEvents(
    artifactId: string,
    handoffId: string,
  ): Promise<string | null>;
  deleteHandoff(artifactId: string, handoffId: string): Promise<void>;
}

const SCHEMA = [
  `CREATE TABLE IF NOT EXISTS artifacts (
    id TEXT PRIMARY KEY,
    token_hash TEXT NOT NULL,
    channel_hash TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    favicon TEXT NOT NULL,
    format TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0,
    current_version INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL,
    owner_id TEXT NOT NULL DEFAULT '',
    org_id TEXT,
    visibility TEXT NOT NULL DEFAULT 'public'
  )`,
  `CREATE TABLE IF NOT EXISTS versions (
    artifact_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    label TEXT,
    title TEXT NOT NULL,
    description TEXT NOT NULL DEFAULT '',
    favicon TEXT NOT NULL,
    format TEXT NOT NULL,
    encrypted INTEGER NOT NULL DEFAULT 0,
    size INTEGER NOT NULL,
    created_at TEXT NOT NULL,
    PRIMARY KEY (artifact_id, version)
  )`,
  // anchor / delete_token_hash / done must also appear in MIGRATIONS below —
  // SCHEMA alone never upgrades an existing production DB (#33).
  `CREATE TABLE IF NOT EXISTS comments (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    author TEXT,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL,
    anchor TEXT,
    delete_token_hash TEXT,
    done INTEGER NOT NULL DEFAULT 0
  )`,
  `CREATE INDEX IF NOT EXISTS idx_comments_artifact_created
    ON comments(artifact_id, created_at)`,
  // Handoff recordings: a creator's webcam+mic walkthrough of an artifact.
  // media + events are R2 objects under handoff/<artifactId>/<handoffId>/; this
  // table holds only metadata. version pins a recording to the artifact
  // snapshot it was captured against so playback re-serves that frame.
  `CREATE TABLE IF NOT EXISTS handoffs (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    media_size INTEGER NOT NULL,
    events_size INTEGER NOT NULL,
    has_video INTEGER NOT NULL DEFAULT 1,
    has_audio INTEGER NOT NULL DEFAULT 1,
    has_blur INTEGER NOT NULL DEFAULT 0,
    author TEXT,
    delete_token_hash TEXT,
    created_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_handoffs_artifact_created
    ON handoffs(artifact_id, created_at)`,
];

// Convention (#33): SCHEMA is the full current shape for fresh DBs; MIGRATIONS
// upgrades existing DBs to catch up. A column added after v1 must appear in
// BOTH — SCHEMA-only never reaches production; MIGRATIONS-only leaves fresh
// installs depending on an ALTER. MIGRATIONS also carries *removals*: when a
// column/table is dropped from SCHEMA, a DROP is appended here so deployed DBs
// shed it (fresh DBs never had it — see the error tolerance below).
//
// Each ADD errors if the column already exists, which is fine — the column is
// there. The unique index makes channel binding race-safe: concurrent first
// publishes to one channel can only mint one artifact (SQLite allows any
// number of NULLs, so channel-less artifacts are unaffected).
const MIGRATIONS = [
  `ALTER TABLE artifacts ADD COLUMN channel_hash TEXT`,
  `ALTER TABLE versions ADD COLUMN title TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE versions ADD COLUMN description TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE versions ADD COLUMN favicon TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE versions ADD COLUMN format TEXT NOT NULL DEFAULT 'html'`,
  `ALTER TABLE versions ADD COLUMN encrypted INTEGER NOT NULL DEFAULT 0`,
  `CREATE UNIQUE INDEX IF NOT EXISTS idx_artifacts_channel_hash ON artifacts(channel_hash)`,
  // Anchored comments (#5): nullable JSON anchor + per-comment delete-token hash.
  // Legacy rows read NULL for both — unanchored and owner-removable only.
  `ALTER TABLE comments ADD COLUMN anchor TEXT`,
  `ALTER TABLE comments ADD COLUMN delete_token_hash TEXT`,
  // Soft "done" / resolved flag — open toggle for all viewers (not delete).
  `ALTER TABLE comments ADD COLUMN done INTEGER NOT NULL DEFAULT 0`,
  // Feedback channel removed: drop its table/index and the artifacts.project_ref
  // column it fed. IF EXISTS makes the table/index drops idempotent no-ops; the
  // column drop throws "no such column" once gone and on fresh DBs, which the
  // error tolerance treats as expected.
  `DROP INDEX IF EXISTS idx_feedback_artifact_status`,
  `DROP TABLE IF EXISTS feedback`,
  `ALTER TABLE artifacts DROP COLUMN project_ref`,
  `ALTER TABLE artifacts ADD COLUMN owner_id TEXT NOT NULL DEFAULT ''`,
  `ALTER TABLE artifacts ADD COLUMN org_id TEXT`,
  `ALTER TABLE artifacts ADD COLUMN visibility TEXT NOT NULL DEFAULT 'public'`,
  `CREATE INDEX IF NOT EXISTS idx_artifacts_owner ON artifacts(owner_id)`,
  `CREATE INDEX IF NOT EXISTS idx_artifacts_org ON artifacts(org_id)`,
  // Handoff recordings (new table): idempotent CREATE so an existing DB picks
  // it up on first request; a fresh DB already has it from SCHEMA above.
  `CREATE TABLE IF NOT EXISTS handoffs (
    id TEXT PRIMARY KEY,
    artifact_id TEXT NOT NULL,
    version INTEGER NOT NULL,
    duration_ms INTEGER NOT NULL,
    media_type TEXT NOT NULL,
    media_size INTEGER NOT NULL,
    events_size INTEGER NOT NULL,
    has_video INTEGER NOT NULL DEFAULT 1,
    has_audio INTEGER NOT NULL DEFAULT 1,
    has_blur INTEGER NOT NULL DEFAULT 0,
    author TEXT,
    delete_token_hash TEXT,
    created_at TEXT NOT NULL
  )`,
  `CREATE INDEX IF NOT EXISTS idx_handoffs_artifact_created
    ON handoffs(artifact_id, created_at)`,
  // has_blur added after the initial handoffs table shipped: existing DBs got
  // the table from the CREATE TABLE IF NOT EXISTS above but without this
  // column. The ALTER is idempotent (duplicate-column error swallowed by
  // isExpectedMigrationError). Fresh DBs already have it from SCHEMA.
  `ALTER TABLE handoffs ADD COLUMN has_blur INTEGER NOT NULL DEFAULT 0`,
  // Per-version handoffs: the id is now scoped by version
  // (h<artifactId>_v<version>) so each version keeps its own recording. Legacy
  // single-handoff rows (h<artifactId>, no _v suffix) are wiped so a stale
  // one-per-artifact row can't shadow the new version-scoped recording for the
  // same version. Idempotent - a second run matches zero rows. R2 media for the
  // wiped rows is NOT swept here (SQL can't touch R2); the artifact-delete
  // prefix sweep handoff/<artifactId>/ covers them when the artifact goes.
  `DELETE FROM handoffs WHERE id NOT LIKE '%\\_v%' ESCAPE '\\'`,
];

// After the ALTERs above add columns to existing rows with empty defaults,
// backfill those rows from the parent artifact so historical versions keep
// their metadata. Runs once per fresh column; a no-op once data is present.
const BACKFILL = `
UPDATE versions
SET title = (SELECT title FROM artifacts WHERE artifacts.id = versions.artifact_id),
    description = (SELECT description FROM artifacts WHERE artifacts.id = versions.artifact_id),
    favicon = (SELECT favicon FROM artifacts WHERE artifacts.id = versions.artifact_id),
    format = (SELECT format FROM artifacts WHERE artifacts.id = versions.artifact_id),
    encrypted = (SELECT encrypted FROM artifacts WHERE artifacts.id = versions.artifact_id)
WHERE title = '' AND favicon = ''
`;

// "duplicate column name": an ADD already ran on this database.
// "UNIQUE constraint failed": the index cannot cover legacy duplicate rows.
// "no such column" on a DROP COLUMN: the column is already gone — every re-run
//   after the first, and every fresh DB where SCHEMA never defined it. Scoped
//   to DROP COLUMN by inspecting the statement, so an unrelated "no such
//   column" from a future migration still surfaces instead of being swallowed.
// Anything else is a genuine failure worth surfacing in the logs.
const isExpectedMigrationError = (error: unknown, sql: string): boolean => {
  if (!(error instanceof Error)) return false;
  if (/\bdrop column\b/i.test(sql) && /no such column/.test(error.message)) {
    return true;
  }
  return /duplicate column name|UNIQUE constraint failed/.test(error.message);
};

// Memoized per database so a second binding (or a fresh test database in the
// same isolate) never skips its own setup. A failed attempt clears the memo,
// so a transient D1 error does not poison every subsequent request — including
// unexpected migration/backfill failures (#33), which used to warn-and-continue
// and permanently memoize success for the isolate's life.
const schemaReady = new WeakMap<D1Database, Promise<unknown>>();

type EnsureSchemaOptions = {
  // Test-only override: run these instead of MIGRATIONS (skips BACKFILL).
  migrations?: readonly string[];
};

async function ensureSchema(
  db: D1Database,
  options?: EnsureSchemaOptions,
): Promise<unknown> {
  const pending = schemaReady.get(db);
  if (pending) return pending;
  const migrations = options?.migrations ?? MIGRATIONS;
  const runBackfill = options?.migrations === undefined;
  const run = async () => {
    await db.batch(SCHEMA.map((sql) => db.prepare(sql)));
    // Statements run via prepare(), not exec(): exec() splits its input on
    // newlines and rejects multi-line statements like BACKFILL. Sequential,
    // not parallel: the unique index depends on the channel_hash ALTER having
    // run first on a pre-channel database. Expected failures (column already
    // added, or an index blocked by legacy duplicate rows) stay silent;
    // anything else rejects so the memo clears and the next request retries.
    for (const sql of migrations) {
      try {
        await db.prepare(sql).run();
      } catch (error) {
        if (!isExpectedMigrationError(error, sql)) {
          console.warn("migration failed:", sql, error);
          throw error;
        }
      }
    }
    // Backfill historical version rows that got empty defaults from the
    // ALTER above. No-op once rows are populated. A real failure must reject
    // so we do not memoize success and skip the backfill forever (#33).
    if (runBackfill) {
      await db.prepare(BACKFILL).run();
    }
  };
  const attempt = run().catch((error) => {
    schemaReady.delete(db);
    throw error;
  });
  schemaReady.set(db, attempt);
  return attempt;
}

/** @internal Test hook — production callers go through D1R2Store. */
export async function ensureSchemaForTests(
  db: D1Database,
  options?: EnsureSchemaOptions,
): Promise<unknown> {
  return ensureSchema(db, options);
}

/** @internal Clears the per-DB schema memo between migration tests. */
export function resetSchemaMemoForTests(db: D1Database): void {
  schemaReady.delete(db);
}

interface ArtifactRow {
  id: string;
  token_hash: string;
  channel_hash: string | null;
  title: string;
  description: string;
  favicon: string;
  format: string;
  encrypted: number;
  current_version: number;
  created_at: string;
  updated_at: string;
  owner_id: string;
  org_id: string | null;
  visibility: string;
}

function toRecord(row: ArtifactRow): ArtifactRecord {
  return {
    id: row.id,
    tokenHash: row.token_hash,
    channelHash: row.channel_hash,
    title: row.title,
    description: row.description,
    favicon: row.favicon,
    format: row.format as ArtifactFormat,
    encrypted: row.encrypted === 1,
    currentVersion: row.current_version,
    createdAt: row.created_at,
    updatedAt: row.updated_at,
    ownerId: row.owner_id ?? "",
    orgId: row.org_id ?? null,
    visibility: (row.visibility ?? "public") as Visibility,
  };
}

const defaultOwnership = (): OwnershipGrant => ({
  ownerId: "",
  orgId: null,
  visibility: "public",
});

const contentKey = (id: string, version: number) => `content/${id}/${version}`;

// Derive a stable, deterministic handoff id from the artifact id + version so
// re-records of the SAME version overwrite the same D1 row + R2 keys in place
// (race-free), while different versions keep independent recordings. The "h"
// prefix keeps the handoff id visually distinct from the artifact id while
// staying in the same URL-safe alphabet; the `_v<N>` suffix scopes the row.
// Two concurrent POSTs for the same artifact+version resolve to the same id
// and the ON CONFLICT DO UPDATE makes the last COMMIT win - no
// list/delete/create window, no orphaned media. Legacy single-handoff rows
// (h<artifactId>, no suffix) are wiped by a MIGRATIONS DELETE on first deploy
// of this change; their R2 media is swept by the artifact-delete prefix sweep.
const handoffIdFor = (artifactId: string, version: number): string =>
  `h${artifactId}_v${version}`;

interface Envelope extends EncryptionParams {
  v: 1;
  alg: "AES-GCM";
  kdf: "PBKDF2-SHA256";
  ciphertext: string;
}

function contentObjectBody(
  content: string,
  encrypted: EncryptionParams | null,
): string {
  if (encrypted === null) return content;
  const envelope: Envelope = {
    v: 1,
    alg: "AES-GCM",
    kdf: "PBKDF2-SHA256",
    iterations: encrypted.iterations,
    salt: encrypted.salt,
    iv: encrypted.iv,
    ciphertext: content,
  };
  return JSON.stringify(envelope);
}

export class D1R2Store implements ArtifactStore {
  constructor(
    private readonly db: D1Database,
    private readonly bucket: R2Bucket,
  ) {}

  async create(
    id: string,
    tokenHash: string,
    input: CreateInput,
    channelHash: string | null,
    ownership: OwnershipGrant | null = null,
  ): Promise<ArtifactRecord> {
    await ensureSchema(this.db);
    const grant = ownership ?? defaultOwnership();
    const now = new Date().toISOString();
    const encrypted = input.encrypted !== null;
    await this.bucket.put(
      contentKey(id, 1),
      contentObjectBody(input.content, input.encrypted),
      {
        customMetadata: { encrypted: encrypted ? "1" : "0" },
      },
    );
    const insert = this.db.batch([
      this.db
        .prepare(
          `INSERT INTO artifacts (id, token_hash, channel_hash, title, description, favicon, format, encrypted, current_version, created_at, updated_at, owner_id, org_id, visibility)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, 1, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id,
          tokenHash,
          channelHash,
          input.title,
          input.description,
          input.favicon,
          input.format,
          input.encrypted ? 1 : 0,
          now,
          now,
          grant.ownerId,
          grant.orgId,
          grant.visibility,
        ),
      this.db
        .prepare(
          `INSERT INTO versions (artifact_id, version, label, title, description, favicon, format, encrypted, size, created_at)
           VALUES (?, 1, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          id,
          input.label,
          input.title,
          input.description,
          input.favicon,
          input.format,
          input.encrypted ? 1 : 0,
          contentByteLength(input.content),
          now,
        ),
    ]);
    // The unique channel index makes a failed insert an expected outcome of
    // racing first publishes; sweep the object written above so the discarded
    // id leaves nothing behind in the bucket.
    await insert.catch(async (error) => {
      await this.bucket.delete(contentKey(id, 1)).catch(() => {});
      throw error;
    });
    return {
      id,
      tokenHash,
      channelHash,
      title: input.title,
      description: input.description,
      favicon: input.favicon,
      format: input.format,
      encrypted: input.encrypted !== null,
      currentVersion: 1,
      createdAt: now,
      updatedAt: now,
      ownerId: grant.ownerId,
      orgId: grant.orgId,
      visibility: grant.visibility,
    };
  }

  async get(id: string): Promise<ArtifactRecord | null> {
    await ensureSchema(this.db);
    const row = await this.db
      .prepare("SELECT * FROM artifacts WHERE id = ?")
      .bind(id)
      .first<ArtifactRow>();
    return row ? toRecord(row) : null;
  }

  async findByChannel(channelHash: string): Promise<ArtifactRecord | null> {
    await ensureSchema(this.db);
    // The unique index caps this at one row; ORDER BY keeps the pick
    // deterministic (oldest binding wins, id as tiebreaker) on a legacy DB
    // where duplicates predate the index.
    const row = await this.db
      .prepare(
        "SELECT * FROM artifacts WHERE channel_hash = ? ORDER BY created_at, id LIMIT 1",
      )
      .bind(channelHash)
      .first<ArtifactRow>();
    return row ? toRecord(row) : null;
  }

  async listArtifactStorage(): Promise<ArtifactStorage[]> {
    await ensureSchema(this.db);
    const { results } = await this.db
      .prepare(
        `SELECT a.id, a.created_at, COALESCE(SUM(v.size), 0) AS total_size
         FROM artifacts AS a
         LEFT JOIN versions AS v ON v.artifact_id = a.id
         GROUP BY a.id, a.created_at
         ORDER BY a.created_at ASC, a.id ASC`,
      )
      .all<{ id: string; created_at: string; total_size: number }>();
    return results.map((row) => ({
      id: row.id,
      createdAt: row.created_at,
      totalSize: row.total_size,
    }));
  }

  async listVersions(id: string): Promise<VersionMeta[]> {
    await ensureSchema(this.db);
    const { results } = await this.db
      .prepare(
        `SELECT version, label, title, description, favicon, format, encrypted, size, created_at
         FROM versions WHERE artifact_id = ? ORDER BY version ASC`,
      )
      .bind(id)
      .all<{
        version: number;
        label: string | null;
        title: string;
        description: string;
        favicon: string;
        format: string;
        encrypted: number;
        size: number;
        created_at: string;
      }>();
    return results.map((row) => ({
      version: row.version,
      label: row.label,
      title: row.title,
      description: row.description,
      favicon: row.favicon,
      format: row.format as ArtifactFormat,
      encrypted: row.encrypted === 1,
      size: row.size,
      createdAt: row.created_at,
    }));
  }

  async getContent(id: string, version: number): Promise<StoredContent | null> {
    const object = await this.bucket.get(contentKey(id, version));
    if (object === null) return null;
    const body = await object.text();
    // Per-version flag, not the artifact's current state: an artifact can
    // switch between encrypted and plain across versions, and each version
    // must be parsed by its own encryption state.
    const encrypted = object.customMetadata?.encrypted === "1";
    if (encrypted) {
      const envelope = JSON.parse(body) as Envelope;
      return {
        body: envelope.ciphertext,
        encrypted: {
          salt: envelope.salt,
          iv: envelope.iv,
          iterations: envelope.iterations,
        },
      };
    }
    return { body, encrypted: null };
  }

  async getContentMeta(
    id: string,
    version: number,
  ): Promise<{ encrypted: boolean } | null> {
    // head() returns the R2 object's metadata without streaming the body —
    // the authoritative per-version encrypted flag, which the versions-table
    // flag is not on legacy mixed-encryption artifacts.
    const object = await this.bucket.head(contentKey(id, version));
    if (object === null) return null;
    return { encrypted: object.customMetadata?.encrypted === "1" };
  }

  async update(
    record: ArtifactRecord,
    input: UpdateInput,
  ): Promise<number | { conflict: true; currentVersion: number }> {
    const now = new Date().toISOString();
    const version = record.currentVersion + 1;
    const encrypted = input.encrypted !== null;

    // Compare-and-swap on D1 first: only advance current_version if it still
    // matches the snapshot we read. This makes concurrent PUTs safe — exactly
    // one wins, the rest get a conflict — and we only write R2 once D1 has
    // accepted the new version, so an R2 object is never orphaned from D1.
    const claimed = await this.db
      .prepare(
        `UPDATE artifacts
         SET title = ?, description = ?, favicon = ?, format = ?, encrypted = ?, current_version = ?, updated_at = ?
         WHERE id = ? AND current_version = ?`,
      )
      .bind(
        input.title ?? record.title,
        input.description ?? record.description,
        input.favicon ?? record.favicon,
        input.format ?? record.format,
        input.encrypted ? 1 : 0,
        version,
        now,
        record.id,
        record.currentVersion,
      )
      .run();

    if (claimed.meta.changes === 0) {
      const fresh = await this.get(record.id);
      return {
        conflict: true,
        currentVersion: fresh?.currentVersion ?? version,
      };
    }

    const vTitle = input.title ?? record.title;
    const vDescription = input.description ?? record.description;
    const vFavicon = input.favicon ?? record.favicon;
    const vFormat = input.format ?? record.format;

    await this.bucket.put(
      contentKey(record.id, version),
      contentObjectBody(input.content, input.encrypted),
      { customMetadata: { encrypted: encrypted ? "1" : "0" } },
    );
    await this.db
      .prepare(
        `INSERT INTO versions (artifact_id, version, label, title, description, favicon, format, encrypted, size, created_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
      .bind(
        record.id,
        version,
        input.label,
        vTitle,
        vDescription,
        vFavicon,
        vFormat,
        input.encrypted ? 1 : 0,
        contentByteLength(input.content),
        now,
      )
      .run();

    return version;
  }

  async replaceCurrent(
    record: ArtifactRecord,
    input: UpdateInput,
  ): Promise<number | { conflict: true; currentVersion: number }> {
    let now = new Date().toISOString();
    if (now === record.updatedAt) {
      now = new Date(Date.now() + 1).toISOString();
    }
    const version = record.currentVersion;
    const encrypted = input.encrypted !== null;
    const title = input.title ?? record.title;
    const description = input.description ?? record.description;
    const favicon = input.favicon ?? record.favicon;
    const format = input.format ?? record.format;

    // Live edits intentionally keep the current version number. The CAS still
    // protects the in-place replacement from overwriting a normal versioned
    // or another Live update that landed after the browser/agent read its
    // snapshot. updated_at is the mutation marker because current_version is
    // intentionally unchanged by this operation.
    const claimed = await this.db
      .prepare(
        `UPDATE artifacts
         SET title = ?, description = ?, favicon = ?, format = ?, encrypted = ?, updated_at = ?
         WHERE id = ? AND current_version = ? AND updated_at = ?`,
      )
      .bind(
        title,
        description,
        favicon,
        format,
        encrypted ? 1 : 0,
        now,
        record.id,
        record.currentVersion,
        record.updatedAt,
      )
      .run();

    if (claimed.meta.changes === 0) {
      const fresh = await this.get(record.id);
      return {
        conflict: true,
        currentVersion: fresh?.currentVersion ?? version,
      };
    }

    await this.bucket.put(
      contentKey(record.id, version),
      contentObjectBody(input.content, input.encrypted),
      { customMetadata: { encrypted: encrypted ? "1" : "0" } },
    );

    // Keep the history row for this version, but refresh the metadata and size
    // that the version picker displays. Its original created_at remains the
    // creation time of the version, not the time of a later Live edit.
    const updated = await this.db
      .prepare(
        `UPDATE versions
         SET label = ?, title = ?, description = ?, favicon = ?, format = ?, encrypted = ?, size = ?
         WHERE artifact_id = ? AND version = ?`,
      )
      .bind(
        input.label,
        title,
        description,
        favicon,
        format,
        encrypted ? 1 : 0,
        contentByteLength(input.content),
        record.id,
        version,
      )
      .run();

    // All current artifacts have a matching versions row, but inserting here
    // keeps a legacy database repairable if that row was missing already.
    if (updated.meta.changes === 0) {
      await this.db
        .prepare(
          `INSERT INTO versions (artifact_id, version, label, title, description, favicon, format, encrypted, size, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        )
        .bind(
          record.id,
          version,
          input.label,
          title,
          description,
          favicon,
          format,
          encrypted ? 1 : 0,
          contentByteLength(input.content),
          record.updatedAt,
        )
        .run();
    }

    return version;
  }

  async delete(id: string): Promise<void> {
    await ensureSchema(this.db);
    // list() returns at most 1000 keys per page (delete() accepts at most as
    // many), so drain page by page — an artifact republished from a channel
    // can easily accumulate more versions than one page holds. The same drain
    // sweeps handoff media+events (handoff/<id>/) alongside content/<id>/.
    for (const prefix of [`content/${id}/`, `handoff/${id}/`]) {
      for (;;) {
        const page = await this.bucket.list({ prefix });
        if (page.objects.length > 0) {
          await this.bucket.delete(page.objects.map((o) => o.key));
        }
        if (!page.truncated) break;
      }
    }
    await this.db.batch([
      this.db.prepare("DELETE FROM versions WHERE artifact_id = ?").bind(id),
      this.db.prepare("DELETE FROM artifacts WHERE id = ?").bind(id),
      this.db.prepare("DELETE FROM comments WHERE artifact_id = ?").bind(id),
      this.db.prepare("DELETE FROM handoffs WHERE artifact_id = ?").bind(id),
    ]);
  }

  async updateVisibility(id: string, visibility: Visibility): Promise<void> {
    await ensureSchema(this.db);
    const now = new Date().toISOString();
    await this.db
      .prepare(
        "UPDATE artifacts SET visibility = ?, updated_at = ? WHERE id = ?",
      )
      .bind(visibility, now, id)
      .run();
  }

  async listComments(artifactId: string): Promise<CommentMeta[]> {
    await ensureSchema(this.db);
    // Cap at 100 to bound inlined HTML. Keep the *newest* window (DESC LIMIT),
    // then reverse so callers still see chronological oldest-first. ASC LIMIT
    // would freeze on the first 100 and hide every subsequent post.
    //
    // Tie-break on rowid, not id: created_at is only millisecond-precise, so a
    // same-millisecond burst ties on it, and id is random — which would make
    // both the order and which 100 survive the cap nondeterministic. rowid is
    // monotonic with insertion. Same fix the feedback poll took (#22).
    const { results } = await this.db
      .prepare(
        `SELECT id, artifact_id, author, body, anchor, done, created_at
         FROM comments WHERE artifact_id = ?
         ORDER BY created_at DESC, rowid DESC LIMIT 100`,
      )
      .bind(artifactId)
      .all<CommentRow>();
    return results.map(toComment).reverse();
  }

  async addComment(
    artifactId: string,
    input: CommentInput,
    deleteTokenHash: string | null = null,
  ): Promise<CommentMeta> {
    await ensureSchema(this.db);
    const id = generateId();
    const now = new Date().toISOString();
    const anchorJson = input.anchor ? JSON.stringify(input.anchor) : null;
    await this.db
      .prepare(
        `INSERT INTO comments (id, artifact_id, author, body, anchor, delete_token_hash, done, created_at)
         VALUES (?, ?, ?, ?, ?, ?, 0, ?)`,
      )
      .bind(
        id,
        artifactId,
        input.author,
        input.body,
        anchorJson,
        deleteTokenHash,
        now,
      )
      .run();
    return {
      id,
      artifactId,
      author: input.author,
      body: input.body,
      anchor: input.anchor,
      done: false,
      createdAt: now,
    };
  }

  // Delete authorization needs only the owning artifact and the stored token
  // hash; the hash never leaves the server and is never part of CommentMeta.
  async getComment(
    commentId: string,
  ): Promise<{ artifactId: string; deleteTokenHash: string | null } | null> {
    await ensureSchema(this.db);
    const row = await this.db
      .prepare(
        "SELECT artifact_id, delete_token_hash FROM comments WHERE id = ?",
      )
      .bind(commentId)
      .first<{ artifact_id: string; delete_token_hash: string | null }>();
    return row
      ? { artifactId: row.artifact_id, deleteTokenHash: row.delete_token_hash }
      : null;
  }

  /** Returns false if the comment row does not exist. */
  async setCommentDone(commentId: string, done: boolean): Promise<boolean> {
    await ensureSchema(this.db);
    const result = await this.db
      .prepare("UPDATE comments SET done = ? WHERE id = ?")
      .bind(done ? 1 : 0, commentId)
      .run();
    return (result.meta.changes ?? 0) > 0;
  }

  async deleteComment(commentId: string): Promise<void> {
    await ensureSchema(this.db);
    await this.db
      .prepare("DELETE FROM comments WHERE id = ?")
      .bind(commentId)
      .run();
  }

  // --- Handoff recordings (webcam+mic media + interaction events in R2) ---

  async listHandoffs(artifactId: string): Promise<HandoffMeta[]> {
    await ensureSchema(this.db);
    const { results } = await this.db
      .prepare(
        `SELECT id, artifact_id, version, duration_ms, media_type, media_size, events_size, has_video, has_audio, has_blur, author, created_at
         FROM handoffs WHERE artifact_id = ? ORDER BY created_at DESC LIMIT 100`,
      )
      .bind(artifactId)
      .all<HandoffRow>();
    return results.map(toHandoff);
  }

  async createHandoff(
    artifactId: string,
    input: HandoffCreateInput,
    media: { body: ReadableStream | string | ArrayBuffer | Blob; size: number },
    events: { json: string; size: number },
    deleteTokenHash: string | null,
  ): Promise<HandoffMeta> {
    await ensureSchema(this.db);
    // One handoff per artifact+version: derive a stable id from the
    // artifactId + version so a re-record of the same version UPSERTs the
    // same D1 row and overwrites the same R2 keys in place - no
    // list/delete/create window, no race, no orphaned media under a
    // discarded id. Concurrent POSTs for the same version converge on the
    // same id and the last COMMIT wins (INSERT ... ON CONFLICT DO UPDATE),
    // exactly one row survives. Different versions get distinct ids, so
    // their recordings coexist independently.
    const id = handoffIdFor(artifactId, input.version);
    const now = new Date().toISOString();
    const mediaKey = `handoff/${artifactId}/${id}/media`;
    const eventsKey = `handoff/${artifactId}/${id}/events`;
    // Write R2 (media + events) then D1. Any failure across the three writes
    // sweeps both R2 objects so a partial write (e.g. media put succeeds, events
    // put fails) never orphans the media under a D1-less id - the create()
    // channel-conflict cleanup pattern, extended to two objects. customMetadata
    // carries the media type so a direct R2 fetch still knows it without a join.
    try {
      await this.bucket.put(mediaKey, media.body, {
        customMetadata: {
          media_type: input.mediaType,
          artifact_id: artifactId,
        },
      });
      await this.bucket.put(eventsKey, events.json, {
        customMetadata: { artifact_id: artifactId },
      });
      await this.db
        .prepare(
          `INSERT INTO handoffs (id, artifact_id, version, duration_ms, media_type, media_size, events_size, has_video, has_audio, has_blur, author, delete_token_hash, created_at)
           VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
           ON CONFLICT(id) DO UPDATE SET
             version = excluded.version,
             duration_ms = excluded.duration_ms,
             media_type = excluded.media_type,
             media_size = excluded.media_size,
             events_size = excluded.events_size,
             has_video = excluded.has_video,
             has_audio = excluded.has_audio,
             has_blur = excluded.has_blur,
             author = excluded.author,
             delete_token_hash = excluded.delete_token_hash,
             created_at = excluded.created_at`,
        )
        .bind(
          id,
          artifactId,
          input.version,
          input.durationMs,
          input.mediaType,
          media.size,
          events.size,
          input.hasVideo ? 1 : 0,
          input.hasAudio ? 1 : 0,
          input.hasBlur ? 1 : 0,
          input.author,
          deleteTokenHash,
          now,
        )
        .run();
    } catch (error) {
      await this.bucket.delete([mediaKey, eventsKey]).catch(() => {});
      throw error;
    }
    return {
      id,
      artifactId,
      version: input.version,
      durationMs: input.durationMs,
      mediaType: input.mediaType,
      mediaSize: media.size,
      eventsSize: events.size,
      hasVideo: input.hasVideo,
      hasAudio: input.hasAudio,
      hasBlur: input.hasBlur,
      author: input.author,
      createdAt: now,
    };
  }

  async getHandoff(
    artifactId: string,
    handoffId: string,
  ): Promise<HandoffMeta | null> {
    await ensureSchema(this.db);
    const row = await this.db
      .prepare(
        "SELECT id, artifact_id, version, duration_ms, media_type, media_size, events_size, has_video, has_audio, has_blur, author, created_at FROM handoffs WHERE id = ? AND artifact_id = ?",
      )
      .bind(handoffId, artifactId)
      .first<HandoffRow>();
    return row ? toHandoff(row) : null;
  }

  // delete_token_hash is server-only (never part of HandoffMeta), mirroring the
  // comment delete-token idiom: the route reads it to authorize a delete.
  async getHandoffAuth(
    artifactId: string,
    handoffId: string,
  ): Promise<{ deleteTokenHash: string | null } | null> {
    await ensureSchema(this.db);
    const row = await this.db
      .prepare(
        "SELECT delete_token_hash FROM handoffs WHERE id = ? AND artifact_id = ?",
      )
      .bind(handoffId, artifactId)
      .first<{ delete_token_hash: string | null }>();
    return row ? { deleteTokenHash: row.delete_token_hash } : null;
  }

  async getHandoffMedia(
    artifactId: string,
    handoffId: string,
  ): Promise<{ body: ReadableStream; mediaType: string } | null> {
    const meta = await this.getHandoff(artifactId, handoffId);
    if (meta === null) return null;
    const object = await this.bucket.get(
      `handoff/${artifactId}/${handoffId}/media`,
    );
    if (object === null) return null;
    return { body: object.body, mediaType: meta.mediaType };
  }

  async getHandoffEvents(
    artifactId: string,
    handoffId: string,
  ): Promise<string | null> {
    // Symmetric with getHandoffMedia: a deleted-but-not-swept events object
    // must never be served for a handoff whose D1 row is gone.
    const meta = await this.getHandoff(artifactId, handoffId);
    if (meta === null) return null;
    const object = await this.bucket.get(
      `handoff/${artifactId}/${handoffId}/events`,
    );
    if (object === null) return null;
    return object.text();
  }

  async deleteHandoff(artifactId: string, handoffId: string): Promise<void> {
    await ensureSchema(this.db);
    await this.bucket.delete([
      `handoff/${artifactId}/${handoffId}/media`,
      `handoff/${artifactId}/${handoffId}/events`,
    ]);
    await this.db
      .prepare("DELETE FROM handoffs WHERE id = ? AND artifact_id = ?")
      .bind(handoffId, artifactId)
      .run();
  }
}

interface CommentRow {
  id: string;
  artifact_id: string;
  author: string | null;
  body: string;
  anchor: string | null;
  done: number | null;
  created_at: string;
}

function toComment(row: CommentRow): CommentMeta {
  return {
    id: row.id,
    artifactId: row.artifact_id,
    author: row.author,
    body: row.body,
    anchor: row.anchor ? (JSON.parse(row.anchor) as Anchor) : null,
    done: row.done === 1,
    createdAt: row.created_at,
  };
}

interface HandoffRow {
  id: string;
  artifact_id: string;
  version: number;
  duration_ms: number;
  media_type: string;
  media_size: number;
  events_size: number;
  has_video: number;
  has_audio: number;
  has_blur: number;
  author: string | null;
  created_at: string;
}

function toHandoff(row: HandoffRow): HandoffMeta {
  return {
    id: row.id,
    artifactId: row.artifact_id,
    version: row.version,
    durationMs: row.duration_ms,
    mediaType: row.media_type,
    mediaSize: row.media_size,
    eventsSize: row.events_size,
    hasVideo: row.has_video === 1,
    hasAudio: row.has_audio === 1,
    hasBlur: row.has_blur === 1,
    author: row.author,
    createdAt: row.created_at,
  };
}
