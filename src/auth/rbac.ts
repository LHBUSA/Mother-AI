import { ApiError } from "../lib/http";

export const ROLES = ["owner", "admin", "security", "approver", "viewer"] as const;
export type Role = (typeof ROLES)[number];

const RANK: Record<Role, number> = { viewer: 0, approver: 1, security: 2, admin: 3, owner: 4 };

export type Permission =
  | "read"
  | "approve"
  | "manage_agents"
  | "manage_policies"
  | "manage_keys"
  | "manage_badge"
  | "manage_org"
  | "manage_members"
  | "manage_security";

const MINIMUM_ROLE: Record<Permission, Role> = {
  read: "viewer",
  approve: "approver",
  manage_agents: "security",
  manage_policies: "security",
  manage_keys: "admin",
  manage_badge: "admin",
  manage_org: "admin",
  manage_members: "admin",
  manage_security: "security",
};

export function can(role: Role, permission: Permission): boolean {
  return RANK[role] >= RANK[MINIMUM_ROLE[permission]];
}

export function requirePermission(role: Role, permission: Permission): void {
  if (!can(role, permission)) {
    throw new ApiError(403, "FORBIDDEN", `Your role (${role}) cannot perform this action.`);
  }
}

/** A member may only grant roles at or below their own. */
export function canGrant(granter: Role, target: Role): boolean {
  return RANK[granter] >= RANK[target];
}

export function permissionsFor(role: Role): Permission[] {
  return (Object.keys(MINIMUM_ROLE) as Permission[]).filter((p) => can(role, p));
}
