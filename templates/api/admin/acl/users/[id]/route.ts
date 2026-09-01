import { MedusaError } from "@medusajs/framework/utils"
import type {
  AuthenticatedMedusaRequest,
  MedusaResponse,
} from "@medusajs/framework/http"
import { ACL_MODULE, keepsAclControl } from "@ipsoftware/medusa-acl"

export const GET = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const roles = await acl.listRolesForUser(req.params.id)

  res.json({ user_id: req.params.id, roles })
}

/** Sets a user's full set of roles (the submitted set replaces the previous one). */
export const POST = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const body = (req.body ?? {}) as Record<string, unknown>
  const targetId = req.params.id
  const actorId = req.auth_context?.actor_id as string

  if (!Array.isArray(body.role_ids)) {
    throw new MedusaError(
      MedusaError.Types.INVALID_DATA,
      "role_ids must be a list of role ids."
    )
  }

  const roleIds = body.role_ids.filter(
    (id): id is string => typeof id === "string"
  )

  // The first assignment in the system turns on access control for
  // everyone — including whoever is making it. So we check the state AFTER
  // the change even when it targets someone else.
  const snapshot = await acl.getLockoutSnapshot(actorId)
  const targetCurrent = await acl.listUserRoles({ user_id: targetId })
  const assignmentCountAfter =
    snapshot.assignmentCount - targetCurrent.length + roleIds.length

  const allowed = keepsAclControl({
    actorRoleIds: targetId === actorId ? roleIds : snapshot.actorRoleIds,
    rolesAfter: snapshot.roles,
    activeAfter: assignmentCountAfter > 0,
    isSuperadmin: (req as any).acl_access?.superadmin === true,
  })

  if (!allowed) {
    // The core maps a MedusaError NOT_ALLOWED to 400; a permission denial
    // should be 403, matching the one the guard sends.
    return res.status(403).json({
      type: "not_allowed",
      message:
        targetId === actorId
          ? "This change would take away your right to manage roles (acl:write)."
          : "This first assignment would turn access control on, and you don't " +
            "hold a role with acl:write yourself — grant yourself a role first.",
      required_permission: "acl:write",
    })
  }

  await acl.setUserRoles(targetId, roleIds)

  res.json({ user_id: targetId, roles: await acl.listRolesForUser(targetId) })
}
