import { model } from "@medusajs/framework/utils"

/**
 * A role assigned to an admin user. `user_id` is plain text, not a foreign
 * key: `user` is a separate Medusa module with its own data model, and
 * modules aren't allowed to hold each other by key. Cleanup after a deleted
 * user is handled by a `user.deleted` subscriber (see `templates/subscribers`
 * in this package).
 */
export const UserRole = model
  .define("acl_user_role", {
    id: model.id({ prefix: "acluserrole" }).primaryKey(),
    user_id: model.text(),
    role_id: model.text(),
  })
  .indexes([
    {
      on: ["user_id", "role_id"],
      unique: true,
    },
  ])

export default UserRole
