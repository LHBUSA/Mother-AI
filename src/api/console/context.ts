import type { Env } from "../../env";
import type { ConsoleSession } from "../../auth/sessions";
import type { Actor } from "../../gateway/audit";
import { ApiError } from "../../lib/http";

export interface ConsoleContext {
  env: Env;
  db: D1Database;
  session: ConsoleSession;
  orgId: string;
  nowMs: number;
  actor: Actor & { type: "user"; id: string; label: string };
  url: URL;
  params: string[];
  body: Record<string, unknown>;
  waitUntil: (p: Promise<unknown>) => void;
}

type Errors = Record<string, string>;

export class Validator {
  readonly errors: Errors = {};
  constructor(private readonly body: Record<string, unknown>) {}

  string(key: string, opts: { min?: number; max: number; pattern?: RegExp; optional?: boolean; lower?: boolean; message?: string }): string | undefined {
    const raw = this.body[key];
    if (raw === undefined || raw === null) {
      if (!opts.optional) this.errors[key] = "is required";
      return undefined;
    }
    if (typeof raw !== "string") {
      this.errors[key] = "must be a string";
      return undefined;
    }
    let v = raw.trim();
    if (opts.lower) v = v.toLowerCase();
    if (v.length < (opts.min ?? 0)) this.errors[key] = opts.min && opts.min > 1 ? `must be at least ${opts.min} characters` : "is required";
    else if (v.length > opts.max) this.errors[key] = `must be at most ${opts.max} characters`;
    else if (opts.pattern && !opts.pattern.test(v)) this.errors[key] = opts.message ?? "has an invalid format";
    else if (/[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]/.test(v)) this.errors[key] = "contains invalid characters";
    return v;
  }

  oneOf<T extends string>(key: string, values: readonly T[], opts: { optional?: boolean } = {}): T | undefined {
    const raw = this.body[key];
    if (raw === undefined || raw === null) {
      if (!opts.optional) this.errors[key] = "is required";
      return undefined;
    }
    if (typeof raw !== "string" || !(values as readonly string[]).includes(raw)) {
      this.errors[key] = `must be one of: ${values.join(", ")}`;
      return undefined;
    }
    return raw as T;
  }

  int(key: string, opts: { min: number; max: number; optional?: boolean }): number | undefined {
    const raw = this.body[key];
    if (raw === undefined || raw === null) {
      if (!opts.optional) this.errors[key] = "is required";
      return undefined;
    }
    if (typeof raw !== "number" || !Number.isInteger(raw) || raw < opts.min || raw > opts.max) {
      this.errors[key] = `must be an integer between ${opts.min} and ${opts.max}`;
      return undefined;
    }
    return raw;
  }

  bool(key: string, opts: { optional?: boolean } = {}): boolean | undefined {
    const raw = this.body[key];
    if (raw === undefined || raw === null) {
      if (!opts.optional) this.errors[key] = "is required";
      return undefined;
    }
    if (typeof raw !== "boolean") {
      this.errors[key] = "must be true or false";
      return undefined;
    }
    return raw;
  }

  assert(): void {
    if (Object.keys(this.errors).length) {
      throw new ApiError(400, "INVALID_REQUEST", "The request failed validation.", { fields: this.errors });
    }
  }
}

export function assertOrgWritable(ctx: ConsoleContext): void {
  if (ctx.session.organization.status !== "active") {
    throw new ApiError(403, "ORGANIZATION_SUSPENDED", "This organization is suspended; changes are disabled.");
  }
}
