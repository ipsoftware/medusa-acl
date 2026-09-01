import { SubscriberArgs, type SubscriberConfig } from "@medusajs/framework"
import { ACL_MODULE } from "@ipsoftware/medusa-acl"

/**
 * Role assignments store `user_id` as plain text (Medusa modules don't link
 * to each other by foreign key), so deleting an admin user would otherwise
 * leave orphaned rows. If a new user were later created with the same id,
 * they'd inherit someone else's permissions.
 */
export default async function userDeletedHandler({
  event: { data },
  container,
}: SubscriberArgs<{ id: string }>) {
  const acl = container.resolve(ACL_MODULE) as any

  await acl.removeUserAssignments(data.id)
}

export const config: SubscriberConfig = {
  event: "user.deleted",
}
