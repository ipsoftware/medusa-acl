import { MedusaError, MedusaService } from "@medusajs/framework/utils"
import { Role } from "./models/role"
import { UserRole } from "./models/user-role"
import { TtlCache } from "./cache"
import { DEFAULT_CACHE_TTL_MS } from "./const"
import {
  mergePermissions,
  normalizePermissions,
  type Permission,
} from "./permissions"
import type { AclModuleOptions, RoleInput, UserAccess } from "./types"

/**
 * `Some Role Name` -> `some-role-name`
 *
 * NFD-normalizes and strips combining diacritical marks (`café` -> `cafe`).
 * A handful of Latin letters have no canonical decomposition (Polish `ł`,
 * Danish `ø`, ...) and fall through to the final `[^a-z0-9]+` cleanup
 * instead of transliterating — safe, just less pretty for those.
 */
function slugify(value: string): string {
  return (value ?? "")
    .toLowerCase()
    .normalize("NFD")
    .replace(/[\u0300-\u036f]/g, "")
    .replace(/[^a-z0-9]+/g, "-")
    .replace(/^-+|-+$/g, "")
    .slice(0, 64)
}

class AclModuleService extends MedusaService({ Role, UserRole }) {
  private readonly accessCache: TtlCache<UserAccess>

  constructor(container: Record<string, unknown>, options: AclModuleOptions = {}) {
    super(...arguments)

    this.accessCache = new TtlCache<UserAccess>(
      options?.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS
    )
  }

  /**
   * A user's permissions, along with whether access control is in effect at
   * all.
   *
   * `active: false` means nobody has been assigned any role yet — in that
   * case the guard lets everything through. This is deliberate: merely
   * installing the module, or preparing roles, must never lock the store
   * owner out of their own dashboard. Enforcement starts the moment the
   * FIRST role is assigned (not when a role is created) — from that point
   * on, accounts without a role get only the baseline set.
   */
  async getAccessForUser(userId: string): Promise<UserAccess> {
    const cached = this.accessCache.get(userId)

    if (cached) {
      return cached
    }

    const [, assignmentCount] = await this.listAndCountUserRoles({}, { take: 1 })

    if (!assignmentCount) {
      const inactive: UserAccess = {
        active: false,
        permissions: [],
        role_ids: [],
      }
      this.accessCache.set(userId, inactive)

      return inactive
    }

    const assignments = await this.listUserRoles({ user_id: userId })
    const roleIds = assignments.map((assignment) => assignment.role_id)
    const roles = roleIds.length ? await this.listRoles({ id: roleIds }) : []

    const access: UserAccess = {
      active: true,
      // With no roles the user gets only the baseline set (just enough
      // reads for the dashboard to boot) — an empty desk, not an error page.
      permissions: mergePermissions(roles.map((role) => role.permissions)),
      role_ids: roleIds,
    }

    this.accessCache.set(userId, access)

    return access
  }

  /** State snapshot needed to check whether someone is about to lock themselves out. */
  async getLockoutSnapshot(actorId: string): Promise<{
    roles: { id: string; permissions: unknown }[]
    actorRoleIds: string[]
    assignmentCount: number
  }> {
    const roles = await this.listRoles({})
    const assignments = await this.listUserRoles({})

    return {
      roles: roles.map((role) => ({
        id: role.id,
        permissions: role.permissions,
      })),
      actorRoleIds: assignments
        .filter((assignment) => assignment.user_id === actorId)
        .map((assignment) => assignment.role_id),
      assignmentCount: assignments.length,
    }
  }

  async listRolesForUser(userId: string) {
    const assignments = await this.listUserRoles({ user_id: userId })
    const roleIds = assignments.map((assignment) => assignment.role_id)

    return roleIds.length ? await this.listRoles({ id: roleIds }) : []
  }

  /** Sets a user's full set of roles (replaces the previous one). */
  async setUserRoles(userId: string, roleIds: string[]): Promise<void> {
    const wanted = [...new Set((roleIds ?? []).filter(Boolean))]

    if (wanted.length) {
      const existing = await this.listRoles({ id: wanted })

      if (existing.length !== wanted.length) {
        const found = new Set(existing.map((role) => role.id))
        throw new MedusaError(
          MedusaError.Types.NOT_FOUND,
          `No such roles: ${wanted.filter((id) => !found.has(id)).join(", ")}`
        )
      }
    }

    const current = await this.listUserRoles({ user_id: userId })
    const currentIds = new Set(current.map((assignment) => assignment.role_id))

    const toRemove = current.filter(
      (assignment) => !wanted.includes(assignment.role_id)
    )
    const toAdd = wanted.filter((roleId) => !currentIds.has(roleId))

    if (toRemove.length) {
      await this.deleteUserRoles(toRemove.map((assignment) => assignment.id))
    }

    if (toAdd.length) {
      await this.createUserRoles(
        toAdd.map((roleId) => ({ user_id: userId, role_id: roleId }))
      )
    }

    // Clear everything, not just this user's entry: the FIRST assignment
    // turns access control on for everyone, and the LAST one turns it off.
    // Other accounts' cached entries would otherwise lie until the TTL expires.
    this.invalidateAccess()
  }

  /**
   * Creates or updates a role. Permissions go through normalization, so a
   * typo (`"products:edit"`) never lands in the database and never creates
   * the false impression that something was granted.
   */
  async saveRole(input: RoleInput) {
    const permissions: Permission[] = normalizePermissions(
      input.permissions ?? []
    )
    const name = (input.name ?? "").trim()

    if (!name) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        "A role must have a name."
      )
    }

    const slug = slugify(input.slug || name) || `role-${Date.now()}`
    const conflicting = await this.listRoles({ slug })

    if (conflicting.some((role) => role.id !== input.id)) {
      throw new MedusaError(
        MedusaError.Types.INVALID_DATA,
        `A role with the slug "${slug}" already exists.`
      )
    }

    const payload = {
      name,
      slug,
      description: input.description ?? null,
      permissions,
    }

    // The permission list rides in a json column, and its DML type is
    // Record<string, unknown> — hence the cast.
    const saved = input.id
      ? await this.updateRoles([{ id: input.id, ...payload }] as any)
      : await this.createRoles([payload] as any)
    const role = Array.isArray(saved) ? saved[0] : saved

    // A permission change must be visible immediately, not after the cache
    // entry expires.
    this.invalidateAccess()

    return role
  }

  /** Removes a role along with its assignments (there's no foreign key with cascade here). */
  async removeRole(roleId: string): Promise<void> {
    const assignments = await this.listUserRoles({ role_id: roleId })

    if (assignments.length) {
      await this.deleteUserRoles(assignments.map((assignment) => assignment.id))
    }

    await this.deleteRoles([roleId])

    this.invalidateAccess()
  }

  /** Cleanup after a deleted admin user. */
  async removeUserAssignments(userId: string): Promise<void> {
    const assignments = await this.listUserRoles({ user_id: userId })

    if (assignments.length) {
      await this.deleteUserRoles(assignments.map((assignment) => assignment.id))
    }

    this.invalidateAccess()
  }

  invalidateAccess(userId?: string): void {
    if (userId) {
      this.accessCache.delete(userId)
      return
    }

    this.accessCache.clear()
  }
}

export default AclModuleService
