// ---------------------------------------------------------------------------
// The glue between the guard and the rest of the application: pulls a
// user's permissions from the ACL module and resolves the emergency
// allowlist (superadmin by email).
//
// The email has to come from the user module, and modules in Medusa 2 are
// isolated from each other — the ACL module has no business reaching into
// the `user` module. So this join happens here, in the HTTP layer, where
// `req.scope` is available.
// ---------------------------------------------------------------------------
import { ACL_MODULE, DEFAULT_CACHE_TTL_MS } from "../const"
import { TtlCache } from "../cache"
import type { AccessResolver, AclAccess, GuardRequest } from "../guard"

/** The user module's key in the container (equivalent to `Modules.USER`). */
const USER_MODULE = "user"

export type AclServiceLike = {
  getAccessForUser: (
    userId: string
  ) => Promise<{ active: boolean; permissions: string[] }>
}

export type CreateAccessResolverOptions = {
  /** Accounts that pass everything — the escape hatch for a misconfigured setup. */
  superadminEmails?: string[]
  cacheTtlMs?: number
  /** Injected in tests. */
  emailCache?: TtlCache<string>
}

/**
 * `ACL_SUPERADMIN_EMAILS` -> a normalized list of addresses. An empty value,
 * and stray commas or spaces, are tolerated since this is a hand-typed
 * environment variable.
 */
export function parseSuperadminEmails(value?: string | null): string[] {
  return (value ?? "")
    .split(",")
    .map((entry) => entry.trim().toLowerCase())
    .filter(Boolean)
}

export function createAccessResolver(
  options: CreateAccessResolverOptions = {}
): AccessResolver {
  const superadmins = new Set(
    parseSuperadminEmails((options.superadminEmails ?? []).join(","))
  )
  const emailCache =
    options.emailCache ??
    new TtlCache<string>(options.cacheTtlMs ?? DEFAULT_CACHE_TTL_MS)

  return async function resolveAccess(
    req: GuardRequest
  ): Promise<AclAccess | null> {
    const actorId = req.auth_context?.actor_id

    if (!actorId) {
      return null
    }

    const acl = req.scope.resolve(ACL_MODULE) as AclServiceLike
    const access = await acl.getAccessForUser(actorId)

    const superadmin = superadmins.size
      ? superadmins.has(await resolveEmail(req, actorId, emailCache))
      : false

    return {
      active: access.active,
      permissions: access.permissions ?? [],
      superadmin,
    }
  }
}

async function resolveEmail(
  req: GuardRequest,
  actorId: string,
  cache: TtlCache<string>
): Promise<string> {
  const cached = cache.get(actorId)

  if (cached !== undefined) {
    return cached
  }

  let email = ""

  try {
    const userModule = req.scope.resolve(USER_MODULE) as {
      retrieveUser: (id: string) => Promise<{ email?: string }>
    }
    const user = await userModule.retrieveUser(actorId)
    email = (user?.email ?? "").toLowerCase()
  } catch {
    // No such user, or the module is unavailable: not a reason to fail the
    // request — it just means this isn't a superadmin.
    email = ""
  }

  cache.set(actorId, email)

  return email
}
