// Minimal D1Database implementation over node:sqlite for integration tests.
// It runs the committed migrations, so triggers and constraints are real.

import { DatabaseSync, type StatementSync } from "node:sqlite";
import { readdirSync, readFileSync } from "node:fs";
import { dirname, join } from "node:path";
import { fileURLToPath } from "node:url";

type Value = string | number | null | bigint | Uint8Array;

function toResult(stmt: StatementSync, params: Value[]) {
  const hasColumns = stmt.columns().length > 0;
  if (hasColumns) {
    const rows = stmt.all(...params) as Record<string, unknown>[];
    return { results: rows, success: true, meta: { changes: 0, last_row_id: 0, duration: 0 } };
  }
  const info = stmt.run(...params);
  return { results: [], success: true, meta: { changes: Number(info.changes), last_row_id: Number(info.lastInsertRowid), duration: 0 } };
}

class ShimStatement {
  constructor(
    private readonly db: DatabaseSync,
    readonly sql: string,
    readonly params: Value[] = [],
  ) {}

  bind(...values: unknown[]): ShimStatement {
    for (const v of values) {
      if (v === undefined) throw new Error("D1_TYPE_ERROR: Type 'undefined' not supported for value 'undefined'");
      if (typeof v === "boolean") throw new Error("D1_TYPE_ERROR: Type 'boolean' not supported");
    }
    return new ShimStatement(this.db, this.sql, values as Value[]);
  }

  execute() {
    return toResult(this.db.prepare(this.sql), this.params);
  }

  async first<T>(column?: string): Promise<T | null> {
    const res = this.execute();
    const row = res.results[0];
    if (!row) return null;
    return (column ? (row[column] as T) : ({ ...row } as T)) ?? null;
  }

  async all<T>() {
    const res = this.execute();
    return { ...res, results: res.results.map((r) => ({ ...r })) as T[] };
  }

  async run() {
    return this.execute();
  }

  async raw() {
    return this.execute().results.map((r) => Object.values(r));
  }
}

export class D1Shim {
  readonly sqlite: DatabaseSync;

  constructor() {
    this.sqlite = new DatabaseSync(":memory:");
    this.sqlite.exec("PRAGMA foreign_keys = ON;");
  }

  static withMigrations(): D1Shim {
    const shim = new D1Shim();
    const dir = join(dirname(fileURLToPath(import.meta.url)), "..", "..", "migrations");
    for (const file of readdirSync(dir).filter((f) => f.endsWith(".sql")).sort()) {
      shim.sqlite.exec(readFileSync(join(dir, file), "utf8"));
    }
    return shim;
  }

  prepare(sql: string): ShimStatement {
    return new ShimStatement(this.sqlite, sql);
  }

  async batch(statements: ShimStatement[]) {
    this.sqlite.exec("BEGIN");
    try {
      const results = statements.map((s) => s.execute());
      this.sqlite.exec("COMMIT");
      return results;
    } catch (err) {
      this.sqlite.exec("ROLLBACK");
      throw err;
    }
  }

  async exec(sql: string) {
    this.sqlite.exec(sql);
    return { count: 0, duration: 0 };
  }

  asD1(): D1Database {
    return this as unknown as D1Database;
  }
}
