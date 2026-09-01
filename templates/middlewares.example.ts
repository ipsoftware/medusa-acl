/**
 * Example wiring for `src/api/middlewares.ts`. This is not meant to be
 * copied verbatim over an existing file — merge the guard registration into
 * whatever middleware config your project already has.
 */
import { defineMiddlewares } from "@medusajs/framework/http"
import {
  createAclGuard,
  createAccessResolver,
  parseSuperadminEmails,
} from "@ipsoftware/medusa-acl"

// The core authenticates `/admin` with its own middleware, registered
// BEFORE the ones in this file (see Medusa's ApiLoader), so `req.auth_context`
// is already set by the time this guard runs. The matcher is a wildcard, and
// wildcard matchers are sorted ahead of static routes — so the guard sits in
// front of every dashboard handler, including ones added later.
const aclGuard = createAclGuard(
  createAccessResolver({
    // Emergency allowlist: accounts on this list pass everything regardless
    // of role. Without it, a bad role configuration can lock the dashboard
    // with no way back in.
    superadminEmails: parseSuperadminEmails(process.env.ACL_SUPERADMIN_EMAILS),
    cacheTtlMs: Number(process.env.ACL_CACHE_TTL_MS ?? 30000),
  })
)

export default defineMiddlewares({
  routes: [
    {
      matcher: "/admin/*",
      middlewares: [aclGuard as any],
    },
    // ... your project's other middleware entries
  ],
})
