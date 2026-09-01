// ---------------------------------------------------------------------------
// Guards against locking yourself out: an administrator can't change roles
// in a way that leaves them without the right to manage roles themselves.
// Without this, one careless edit to your own role leaves the store with
// nobody able to undo it (short of the emergency allowlist in
// ACL_SUPERADMIN_EMAILS, which is easy to forget about).
// ---------------------------------------------------------------------------
import { hasPermission, mergePermissions } from "../permissions"

/** The permission required to manage access control itself. */
export const ACL_CONTROL_PERMISSION = "acl:write"

export type RoleLike = { id: string; permissions?: unknown }

export type LockoutCheckInput = {
  /** The roles the actor performing the operation will have after the change. */
  actorRoleIds: string[]
  /** All roles after the change (with the edited/removed one already applied). */
  rolesAfter: RoleLike[]
  /** Whether any assignment exists after the change — i.e. whether access control is active. */
  activeAfter: boolean
  /** An account on the emergency allowlist passes everything, so it can never be locked out. */
  isSuperadmin?: boolean
}

/**
 * Whether the actor performing the change still retains role-management
 * rights afterward.
 */
export function keepsAclControl({
  actorRoleIds,
  rolesAfter,
  activeAfter,
  isSuperadmin = false,
}: LockoutCheckInput): boolean {
  if (isSuperadmin) {
    return true
  }

  // No assignments left = access control isn't in effect (see
  // getAccessForUser), so nobody gets locked out. Only the first assignment
  // turns the check on.
  if (!activeAfter) {
    return true
  }

  const assigned = new Set(actorRoleIds)
  const permissions = mergePermissions(
    rolesAfter
      .filter((role) => assigned.has(role.id))
      .map((role) => role.permissions)
  )

  return hasPermission(permissions, ACL_CONTROL_PERMISSION)
}
