import type {
  AuthenticatedMedusaRequest,
  MedusaResponse,
} from "@medusajs/framework/http"
import { ACL_MODULE, keepsAclControl, normalizePermissions } from "@ipsoftware/medusa-acl"

export const GET = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const role = await acl.retrieveRole(req.params.id)
  const assignments = await acl.listUserRoles({ role_id: role.id })

  res.json({
    role: {
      ...role,
      permissions: role.permissions ?? [],
      user_ids: assignments.map((a: any) => a.user_id),
    },
  })
}

export const POST = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const body = (req.body ?? {}) as Record<string, unknown>
  const roleId = req.params.id
  const actorId = req.auth_context?.actor_id as string

  const current = await acl.retrieveRole(roleId)
  const permissions = Array.isArray(body.permissions)
    ? normalizePermissions(body.permissions)
    : (current.permissions ?? [])

  // Whether, after this edit, the person making it can still manage roles.
  const snapshot = await acl.getLockoutSnapshot(actorId)
  const allowed = keepsAclControl({
    actorRoleIds: snapshot.actorRoleIds,
    rolesAfter: snapshot.roles.map((role: any) =>
      role.id === roleId ? { ...role, permissions } : role
    ),
    activeAfter: snapshot.assignmentCount > 0,
    isSuperadmin: (req as any).acl_access?.superadmin === true,
  })

  if (!allowed) {
    // A response of our own instead of MedusaError: the core maps
    // NOT_ALLOWED to 400, and this is a permission denial, so it should
    // look like the one the guard sends.
    return res.status(403).json({
      type: "not_allowed",
      message:
        "This change would take away your right to manage roles (acl:write). " +
        "Grant it to another role you hold first.",
      required_permission: "acl:write",
    })
  }

  const role = await acl.saveRole({
    id: roleId,
    name: typeof body.name === "string" ? body.name : current.name,
    slug: typeof body.slug === "string" ? body.slug : current.slug,
    description:
      typeof body.description === "string" || body.description === null
        ? (body.description as string | null)
        : current.description,
    permissions,
  })

  res.json({ role })
}

export const DELETE = async (req: AuthenticatedMedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const roleId = req.params.id
  const actorId = req.auth_context?.actor_id as string

  const snapshot = await acl.getLockoutSnapshot(actorId)
  const removedAssignments = await acl.listUserRoles({ role_id: roleId })

  const allowed = keepsAclControl({
    actorRoleIds: snapshot.actorRoleIds.filter((id: string) => id !== roleId),
    rolesAfter: snapshot.roles.filter((role: any) => role.id !== roleId),
    activeAfter: snapshot.assignmentCount - removedAssignments.length > 0,
    isSuperadmin: (req as any).acl_access?.superadmin === true,
  })

  if (!allowed) {
    return res.status(403).json({
      type: "not_allowed",
      message:
        "Deleting this role would take away your right to manage roles (acl:write).",
      required_permission: "acl:write",
    })
  }

  await acl.removeRole(roleId)

  res.json({ id: roleId, object: "acl_role", deleted: true })
}
