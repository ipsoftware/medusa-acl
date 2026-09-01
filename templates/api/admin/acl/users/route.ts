import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import { ACL_MODULE } from "@ipsoftware/medusa-acl"

/**
 * Admin users along with their assigned roles. Users come from the `user`
 * module, roles from this package's — joined here, in the HTTP layer,
 * because modules in Medusa 2 aren't allowed to reach into each other.
 */
export const GET = async (req: MedusaRequest, res: MedusaResponse) => {
  const acl = req.scope.resolve(ACL_MODULE) as any
  const userModule = req.scope.resolve("user") as any

  const users = await userModule.listUsers({})
  const assignments = await acl.listUserRoles({})
  const roles = await acl.listRoles({})
  const roleById = new Map(roles.map((role: any) => [role.id, role]))

  res.json({
    users: users.map((user: any) => ({
      id: user.id,
      email: user.email,
      first_name: user.first_name,
      last_name: user.last_name,
      roles: assignments
        .filter((assignment: any) => assignment.user_id === user.id)
        .map((assignment: any) => roleById.get(assignment.role_id))
        .filter(Boolean)
        .map((role: any) => ({ id: role.id, name: role.name, slug: role.slug })),
    })),
  })
}
