import { model } from "@medusajs/framework/utils"

/**
 * A role is a named list of permissions. Permissions are stored as a JSON
 * list, not a separate lookup table: the set of possible permissions comes
 * from the admin API's routes, i.e. from code, not from data. A lookup
 * table would need to be kept in sync with that code on every Medusa
 * update, and would quietly drift out of sync sooner or later.
 */
export const Role = model.define("acl_role", {
  id: model.id({ prefix: "aclrole" }).primaryKey(),
  name: model.text().searchable(),
  slug: model.text().unique(),
  description: model.text().nullable(),
  permissions: model.json().nullable(),
})

export default Role
