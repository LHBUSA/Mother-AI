// Request validation and normalization. Direct API actions and MCP tool calls
// both become a NormalizedAction before any policy is evaluated.

import { ApiError } from "../lib/http";
import type { NormalizedAction } from "./policy-engine";

export const CONTEXT_MAX_BYTES = 8 * 1024;
const CONTEXT_MAX_DEPTH = 6;
const CONTEXT_MAX_KEYS = 64;

const REQUEST_ID = /^[A-Za-z0-9._:-]{1,128}$/;
export const AGENT_KEY = /^[a-z0-9][a-z0-9._-]{0,127}$/;
const TOKEN = /^[a-z0-9][a-z0-9._:/-]{0,127}$/;
const SHORT_TOKEN = /^[a-z0-9][a-z0-9._-]{0,63}$/;
const MCP_NAME = /^[A-Za-z0-9][A-Za-z0-9._:/-]{0,127}$/;
const PRINTABLE = /^[^\x00-\x1f\x7f]{1,512}$/;
export const ENVIRONMENTS = ["production", "staging", "development"] as const;

export interface NormalizedRequest {
  requestId: string | null;
  action: NormalizedAction;
  contextBytes: number;
}

type FieldErrors = Record<string, string>;

function invalid(fields: FieldErrors): never {
  throw new ApiError(400, "INVALID_REQUEST", "The request failed validation.", { fields });
}

function checkKeys(body: Record<string, unknown>, allowed: string[], errors: FieldErrors): void {
  for (const key of Object.keys(body)) {
    if (!allowed.includes(key)) errors[key] = "unknown field";
  }
}

function optionalString(
  body: Record<string, unknown>,
  key: string,
  pattern: RegExp,
  errors: FieldErrors,
  transform: (v: string) => string = (v) => v,
): string | null {
  const v = body[key];
  if (v === undefined || v === null) return null;
  if (typeof v !== "string") {
    errors[key] = "must be a string";
    return null;
  }
  const t = transform(v.trim());
  if (!pattern.test(t)) {
    errors[key] = "has an invalid format";
    return null;
  }
  return t;
}

function requiredString(
  body: Record<string, unknown>,
  key: string,
  pattern: RegExp,
  errors: FieldErrors,
  transform?: (v: string) => string,
): string {
  if (body[key] === undefined || body[key] === null || body[key] === "") {
    errors[key] = "is required";
    return "";
  }
  return optionalString(body, key, pattern, errors, transform) ?? "";
}

const lower = (v: string) => v.toLowerCase();

function validateContext(raw: unknown, key: string, errors: FieldErrors): { value: Record<string, unknown>; bytes: number } {
  if (raw === undefined || raw === null) return { value: {}, bytes: 2 };
  if (typeof raw !== "object" || Array.isArray(raw)) {
    errors[key] = "must be a JSON object";
    return { value: {}, bytes: 0 };
  }
  const serialized = JSON.stringify(raw);
  const bytes = new TextEncoder().encode(serialized).byteLength;
  if (bytes > CONTEXT_MAX_BYTES) {
    errors[key] = `must be at most ${CONTEXT_MAX_BYTES} bytes when serialized`;
    return { value: {}, bytes };
  }
  const walk = (node: unknown, depth: number): string | null => {
    if (depth > CONTEXT_MAX_DEPTH) return `nesting deeper than ${CONTEXT_MAX_DEPTH} levels`;
    if (Array.isArray(node)) {
      for (const item of node) {
        const e = walk(item, depth + 1);
        if (e) return e;
      }
    } else if (node && typeof node === "object") {
      const entries = Object.entries(node);
      if (entries.length > CONTEXT_MAX_KEYS) return `more than ${CONTEXT_MAX_KEYS} keys in one object`;
      for (const [, v] of entries) {
        const e = walk(v, depth + 1);
        if (e) return e;
      }
    } else if (typeof node === "number" && !Number.isFinite(node)) {
      return "non-finite number";
    }
    return null;
  };
  const problem = walk(raw, 1);
  if (problem) errors[key] = `is not allowed: ${problem}`;
  // Re-parse to drop prototypes/getters and freeze the evaluated shape.
  return { value: JSON.parse(serialized) as Record<string, unknown>, bytes };
}

const EVALUATE_FIELDS = [
  "request_id",
  "agent_id",
  "protocol",
  "capability",
  "operation",
  "resource",
  "destination",
  "data_class",
  "environment",
  "context",
  "mcp",
];

/** POST /v1/evaluate body. */
export function normalizeEvaluateRequest(body: Record<string, unknown>): NormalizedRequest {
  const errors: FieldErrors = {};
  checkKeys(body, EVALUATE_FIELDS, errors);

  const requestId = optionalString(body, "request_id", REQUEST_ID, errors);
  const agent = requiredString(body, "agent_id", AGENT_KEY, errors, lower);
  let protocol: "api" | "mcp" = "api";
  if (body.protocol !== undefined && body.protocol !== null) {
    if (body.protocol === "api" || body.protocol === "mcp") protocol = body.protocol;
    else errors.protocol = 'must be "api" or "mcp"';
  }
  const capability = requiredString(body, "capability", TOKEN, errors, lower);
  const operation = requiredString(body, "operation", TOKEN, errors, lower);
  const resource = optionalString(body, "resource", PRINTABLE, errors);
  const destination = optionalString(body, "destination", SHORT_TOKEN, errors, lower);
  const dataClass = optionalString(body, "data_class", SHORT_TOKEN, errors, lower);
  const environment = parseEnvironment(body.environment, errors);
  const context = validateContext(body.context, "context", errors);

  let mcpServer: string | null = null;
  let mcpTool: string | null = null;
  if (body.mcp !== undefined && body.mcp !== null) {
    if (typeof body.mcp !== "object" || Array.isArray(body.mcp)) {
      errors.mcp = "must be an object with server and tool";
    } else {
      const mcp = body.mcp as Record<string, unknown>;
      const mcpErrors: FieldErrors = {};
      checkKeys(mcp, ["server", "tool"], mcpErrors);
      mcpServer = requiredString(mcp, "server", MCP_NAME, mcpErrors);
      mcpTool = requiredString(mcp, "tool", MCP_NAME, mcpErrors);
      for (const [k, v] of Object.entries(mcpErrors)) errors[`mcp.${k}`] = v;
    }
  }
  if (protocol === "mcp" && (!mcpServer || !mcpTool) && !errors.mcp && !errors["mcp.server"] && !errors["mcp.tool"]) {
    errors.mcp = 'is required when protocol is "mcp"';
  }
  if (protocol === "api" && body.mcp !== undefined && body.mcp !== null) {
    errors.mcp = 'is only allowed when protocol is "mcp"';
  }

  if (Object.keys(errors).length) invalid(errors);

  return {
    requestId,
    contextBytes: context.bytes,
    action: {
      agent,
      environment,
      protocol,
      capability,
      operation,
      resource,
      destination,
      data_class: dataClass,
      mcp_server: mcpServer,
      mcp_tool: mcpTool,
      context: context.value,
    },
  };
}

const MCP_FIELDS = ["request_id", "agent_id", "server", "tool", "arguments", "resource", "destination", "data_class", "environment"];

/**
 * POST /v1/mcp/evaluate body. An MCP tool call becomes:
 *   protocol = "mcp", capability = server (lowercased), operation = tool (lowercased),
 *   mcp.server / mcp.tool = exact names, context = tool arguments.
 */
export function normalizeMcpRequest(body: Record<string, unknown>): NormalizedRequest {
  const errors: FieldErrors = {};
  checkKeys(body, MCP_FIELDS, errors);
  const requestId = optionalString(body, "request_id", REQUEST_ID, errors);
  const agent = requiredString(body, "agent_id", AGENT_KEY, errors, lower);
  const server = requiredString(body, "server", MCP_NAME, errors);
  const tool = requiredString(body, "tool", MCP_NAME, errors);
  const resource = optionalString(body, "resource", PRINTABLE, errors);
  const destination = optionalString(body, "destination", SHORT_TOKEN, errors, lower);
  const dataClass = optionalString(body, "data_class", SHORT_TOKEN, errors, lower);
  const environment = parseEnvironment(body.environment, errors);
  const args = validateContext(body.arguments, "arguments", errors);
  if (server && !TOKEN.test(server.toLowerCase())) errors.server = "has an invalid format";
  if (tool && !TOKEN.test(tool.toLowerCase())) errors.tool = "has an invalid format";

  if (Object.keys(errors).length) invalid(errors);

  return {
    requestId,
    contextBytes: args.bytes,
    action: {
      agent,
      environment,
      protocol: "mcp",
      capability: server.toLowerCase(),
      operation: tool.toLowerCase(),
      resource,
      destination,
      data_class: dataClass,
      mcp_server: server,
      mcp_tool: tool,
      context: args.value,
    },
  };
}

function parseEnvironment(raw: unknown, errors: FieldErrors): string | null {
  if (raw === undefined || raw === null) return null;
  if (typeof raw !== "string" || !(ENVIRONMENTS as readonly string[]).includes(raw.toLowerCase())) {
    errors.environment = `must be one of ${ENVIRONMENTS.join(", ")}`;
    return null;
  }
  return raw.toLowerCase();
}
