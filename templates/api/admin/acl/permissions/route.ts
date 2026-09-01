import type { MedusaRequest, MedusaResponse } from "@medusajs/framework/http"
import { ACTIONS, BASELINE_PERMISSIONS, permissionCatalog } from "@ipsoftware/medusa-acl"

/** Permission dictionary for the UI — resource groups and actions. */
export const GET = async (_req: MedusaRequest, res: MedusaResponse) => {
  res.json({
    groups: permissionCatalog(),
    actions: ACTIONS,
    baseline: BASELINE_PERMISSIONS,
  })
}
