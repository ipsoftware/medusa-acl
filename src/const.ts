// Module constants live in their own file, with no imports from @medusajs/*.
// This keeps the decision logic (guard, access, permissions) free of the
// framework, so it can be unit-tested without a Medusa container.

export const ACL_MODULE = "acl"

/** Admin API prefix — everything below it is subject to access control. */
export const ADMIN_PREFIX = "/admin"

/** Default time-to-live for a cached permission entry (ms). */
export const DEFAULT_CACHE_TTL_MS = 30_000
