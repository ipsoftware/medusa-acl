import type {
  AuthenticatedMedusaRequest,
  MedusaResponse,
} from "@medusajs/framework/http"
import {
  ACL_MODULE,
  aclOptionsFromEnv,
  createSuperadminResolver,
} from "@ipsoftware/medusa-acl"

// The guard waves this route through without resolving access (it is on the
// always-allowed list), so `req.acl_access` never reaches it and the
// superadmin flag has to be resolved here — from the same configuration the
// guard uses, or the two will disagree.
const isSuperadmin = createSuperadminResolver(aclOptionsFromEnv())

/**
 * The signed-in admin's own permissions. Always reachable (see the
 * always-allowed list in the package's `permissions` module) — the
 * dashboard needs to know what to hide before it renders anything.
 *
 * `superadmin` matters as much as `permissions` here: an account on the
 * emergency allowlist holds no role, so by permissions alone it looks like an
 * account with no access, while the guard lets it through everywhere. Gate
 * your dashboard with `accessAllows(me, "acl:write")` rather than by
 * inspecting the permission strings yourself.
 */
export const GET = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const userId = req.auth_context?.actor_id

  const access = await acl.getAccessForUser(userId)
  const roles = access.active ? await acl.listRolesForUser(userId) : []

  res.json({
    user_id: userId,
    active: access.active,
    superadmin: await isSuperadmin(req as any, userId as string),
    permissions: access.permissions,
    roles: roles.map((role: any) => ({
      id: role.id,
      name: role.name,
      slug: role.slug,
    })),
  })
}
