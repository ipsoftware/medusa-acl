import { MedusaError } from "@medusajs/framework/utils"
import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import { ACL_MODULE } from "@ipsoftware/medusa-acl"

/** The list of roles, each with its assigned-user count. */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any

  const roles = await acl.listRoles({})
  const assignments = await acl.listUserRoles({})

  res.json({
    roles: roles.map((role: any) => ({
      ...role,
      permissions: role.permissions ?? [],
      user_count: assignments.filter((a: any) => a.role_id === role.id).length,
    })),
    // Access control isn't in effect until someone has been assigned a
    // role. The dashboard needs to show this, so nobody assumes the store
    // is already locked down.
    active: assignments.length > 0,
  })
}

export const POST = async (req: MedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const body = (req.body ?? {}) as Record<string, unknown>

  if (typeof body.name !== "string") {
    throw new MedusaError(MedusaError.Types.INVALID_DATA, "Role name is required.")
  }

  // Creating a role doesn't take anything away from anyone — permissions
  // only change on assignment, so there's no lockout check here.
  const role = await acl.saveRole({
    name: body.name,
    slug: typeof body.slug === "string" ? body.slug : undefined,
    description:
      typeof body.description === "string" ? body.description : null,
    permissions: Array.isArray(body.permissions) ? body.permissions : [],
  })

  res.status(201).json({ role })
}
