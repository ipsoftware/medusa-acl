// ---------------------------------------------------------------------------
// Admin request guard. Sits in the middleware chain after authentication and
// lets a request through only when the user's roles cover the permission
// derived from its path and method.
//
// The access decision is injected (`AccessResolver`), so this file knows
// nothing about a database or a Medusa container and is testable with plain
// mocks.
// ---------------------------------------------------------------------------
import { accessAllows, permissionForRequest } from "../permissions"

export type AclAccess = {
  /** Whether access control is in effect at all — i.e. whether any role has been assigned yet. */
  active: boolean
  /** An account from the emergency allowlist — passes everything. */
  superadmin: boolean
  permissions: string[]
}

export type GuardRequest = {
  method: string
  originalUrl?: string
  url?: string
  path?: string
  auth_context?: { actor_id?: string; actor_type?: string }
  scope: { resolve: (key: string) => any }
  /** The resolved decision is stashed on the request — the /admin/acl routes reuse it. */
  acl_access?: AclAccess
}

export type GuardResponse = {
  status: (code: number) => GuardResponse
  json: (body: any) => any
}

export type AccessResolver = (req: GuardRequest) => Promise<AclAccess | null>

export type GuardLogger = { warn: (message: string) => void }

/** The request's full path — `originalUrl`, because the middleware can be mounted below the root. */
export function requestPath(req: GuardRequest): string {
  return req.originalUrl || req.url || req.path || ""
}

export function createAclGuard(
  resolveAccess: AccessResolver,
  logger?: GuardLogger
) {
  return async function aclGuard(
    req: GuardRequest,
    res: GuardResponse,
    next: (error?: any) => void
  ): Promise<void> {
    let required: string | null | false

    try {
      required = permissionForRequest(req.method, requestPath(req))
    } catch {
      required = false
    }

    // Out of scope for access control: a non-admin path, an unclassified
    // method (OPTIONS), or a route on the always-allowed list.
    if (required === null) {
      return next()
    }

    const actorId = req.auth_context?.actor_id
    const actorType = req.auth_context?.actor_type

    // No auth context — the core will handle the response (401). We don't
    // fake a 403 here, since that would obscure the real reason for the denial.
    if (!actorId || (actorType && actorType !== "user")) {
      return next()
    }

    let access: AclAccess | null

    try {
      access = await resolveAccess(req)
    } catch (error) {
      return next(error)
    }

    if (access) {
      req.acl_access = access
    }

    // The decision itself lives in `accessAllows` (permissions module), shared
    // with whatever gates your dashboard. It carries the escape hatches: no
    // verdict, ACL not configured yet (nobody has been assigned a role), and
    // superadmin. Passing `null` instead of `required` marks a path we cannot
    // classify — the escape hatches still apply, but there is no concrete
    // permission left to check.
    if (accessAllows(access, required === false ? null : required)) {
      return next()
    }

    if (required === false) {
      // An admin path we can't map to a resource. We deny — under access
      // control, not knowing has to mean "no".
      logger?.warn(
        `[acl] cannot classify path ${requestPath(req)} — denying`
      )
    }

    res.status(403).json({
      type: "not_allowed",
      message:
        required === false
          ? "You don't have permission for this resource."
          : `Missing permission "${required}".`,
      required_permission: required === false ? null : required,
    })
  }
}
