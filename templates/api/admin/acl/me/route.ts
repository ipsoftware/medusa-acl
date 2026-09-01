import type {
  AuthenticatedMedusaRequest,
  MedusaResponse,
} from "@medusajs/framework/http"
import { ACL_MODULE } from "@ipsoftware/medusa-acl"

/**
 * The signed-in admin's own permissions. Always reachable (see the
 * always-allowed list in the package's `permissions` module) — the
 * dashboard needs to know what to hide before it renders anything.
 */
export const GET = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const userId = req.auth_context?.actor_id

  const access = await acl.getAccessForUser(userId)
  const roles = access.active ? await acl.listRolesForUser(userId) : []

  res.json({
    user_id: userId,
    active: access.active,
    permissions: access.permissions,
    roles: roles.map((role: any) => ({
      id: role.id,
      name: role.name,
      slug: role.slug,
    })),
  })
}
