// ---------------------------------------------------------------------------
// Pure permission logic: the resource catalog, parsing and matching of
// permission entries, and mapping an HTTP request to the permission it
// requires.
//
// Deliberately free of any @medusajs/* import — this is where the
// allow/deny decision is made, so it needs to be testable without a
// database, a container, or the rest of the application.
// ---------------------------------------------------------------------------

/** Action derived from the HTTP method. */
export type Action = "read" | "write" | "delete"

export const ACTIONS: readonly Action[] = ["read", "write", "delete"] as const

export const WILDCARD = "*"

/** A permission in `resource:action` form, e.g. `products:write`. */
export type Permission = string

export type ParsedPermission = {
  resource: string
  action: Action | typeof WILDCARD
}

/**
 * Admin API resources, grouped for the UI. This list is a hint for humans,
 * NOT a closed set: the guard derives the resource straight from the request
 * path, so a route outside this list is still subject to the check (it only
 * passes with a wildcard or an explicitly added entry).
 *
 * Extend this list with your project's own custom admin routes so they show
 * up in the permission picker — the guard already protects them either way.
 */
export const RESOURCE_GROUPS: readonly { label: string; resources: readonly string[] }[] = [
  {
    label: "Catalog",
    resources: [
      "products",
      "product-categories",
      "product-collections",
      "product-tags",
      "product-types",
      "product-variants",
      "inventory-items",
      "stock-locations",
      "reservations",
      "price-lists",
      "price-preferences",
    ],
  },
  {
    label: "Sales",
    resources: [
      "orders",
      "draft-orders",
      "returns",
      "exchanges",
      "claims",
      "order-edits",
      "fulfillments",
      "payments",
      "payment-collections",
      "return-reasons",
      "refund-reasons",
    ],
  },
  {
    label: "Customers",
    resources: ["customers", "customer-groups"],
  },
  {
    label: "Marketing",
    resources: ["promotions", "campaigns"],
  },
  {
    label: "Settings",
    resources: [
      "regions",
      "sales-channels",
      "shipping-options",
      "shipping-profiles",
      "tax-rates",
      "tax-regions",
      "currencies",
      "stores",
      "uploads",
    ],
  },
  {
    label: "System",
    resources: ["users", "invites", "api-keys", "workflows-executions", "notifications", "plugins", "acl"],
  },
]

export const KNOWN_RESOURCES: readonly string[] = RESOURCE_GROUPS.flatMap(
  (group) => group.resources
)

/**
 * Permissions every authenticated admin user has, regardless of role.
 * Without them the admin dashboard can't even boot: `stores` and
 * `currencies` are read on startup, before any screen renders, and
 * `regions` is read while rendering prices. Deliberately minimal and
 * read-only.
 */
export const BASELINE_PERMISSIONS: readonly Permission[] = [
  "stores:read",
  "currencies:read",
  "regions:read",
]

/** Paths available to every authenticated admin user. */
const ALWAYS_ALLOWED: readonly { method: string; path: string }[] = [
  // The dashboard asks about itself right after login — blocking this logs
  // the user back out.
  { method: "GET", path: "/admin/users/me" },
  // Own permissions: the dashboard needs to know what to hide.
  { method: "GET", path: "/admin/acl/me" },
]

/**
 * HTTP method -> action. `null` means a method we don't classify (OPTIONS is
 * consumed by CORS before it ever reaches us, so there's nothing to guard).
 */
export function actionForMethod(method: string): Action | null {
  switch ((method || "").toUpperCase()) {
    case "GET":
    case "HEAD":
      return "read"
    case "POST":
    case "PUT":
    case "PATCH":
      return "write"
    case "DELETE":
      return "delete"
    default:
      return null
  }
}

/**
 * Path -> resource. Takes the first segment after `/admin`, since that's
 * the granularity the admin API works at (`/admin/products/prod_1/variants`
 * is still `products`). `null` means it can't be classified.
 */
export function resourceForPath(path: string): string | null {
  const clean = (path || "").split("?")[0].split("#")[0]
  const segments = clean.split("/").filter(Boolean)

  if (segments[0] !== "admin") {
    return null
  }

  const resource = (segments[1] || "").toLowerCase()

  return /^[a-z0-9][a-z0-9-_]*$/.test(resource) ? resource : null
}

/** Whether a path belongs to the admin API at all. */
export function isAdminPath(path: string): boolean {
  const clean = (path || "").split("?")[0].split("#")[0]

  return clean === "/admin" || clean.startsWith("/admin/")
}

/** Routes exempt from the check — needed just to open the dashboard at all. */
export function isAlwaysAllowed(method: string, path: string): boolean {
  const clean = (path || "").split("?")[0].split("#")[0].replace(/\/+$/, "")
  const upper = (method || "").toUpperCase()

  return ALWAYS_ALLOWED.some(
    (entry) => entry.method === upper && entry.path === clean
  )
}

/**
 * Parses one permission entry. Accepts `*` (everything), `products`
 * (shorthand for `products:*`), and `resource:action`. Returns `null` for
 * garbage — so a typo in a role never quietly grants broader access than
 * intended.
 */
export function parsePermission(value: string): ParsedPermission | null {
  // This value comes out of a JSON column, so the input can be a number or
  // null — never trust the declared type.
  if (typeof value !== "string") {
    return null
  }

  const normalized = value.trim().toLowerCase()

  if (!normalized) {
    return null
  }

  if (normalized === WILDCARD) {
    return { resource: WILDCARD, action: WILDCARD }
  }

  const parts = normalized.split(":")

  if (parts.length > 2) {
    return null
  }

  const [resource, action = WILDCARD] = parts

  if (!/^([a-z0-9][a-z0-9-_]*|\*)$/.test(resource)) {
    return null
  }

  if (action !== WILDCARD && !ACTIONS.includes(action as Action)) {
    return null
  }

  return { resource, action: action as Action | typeof WILDCARD }
}

/** Drops garbage, normalizes formatting, and removes duplicates (sorted). */
export function normalizePermissions(values: unknown): Permission[] {
  if (!Array.isArray(values)) {
    return []
  }

  const result = new Set<Permission>()

  for (const value of values) {
    if (typeof value !== "string") {
      continue
    }

    const parsed = parsePermission(value)

    if (parsed) {
      result.add(
        parsed.resource === WILDCARD && parsed.action === WILDCARD
          ? WILDCARD
          : `${parsed.resource}:${parsed.action}`
      )
    }
  }

  return [...result].sort()
}

/** Sum of the permissions from several roles, plus the baseline set. */
export function mergePermissions(
  rolePermissions: readonly unknown[]
): Permission[] {
  return normalizePermissions([
    ...BASELINE_PERMISSIONS,
    ...rolePermissions.flatMap((entry) =>
      Array.isArray(entry) ? entry : []
    ),
  ])
}

/** Whether a set of granted permissions covers the required `resource:action`. */
export function hasPermission(
  granted: readonly string[],
  required: string
): boolean {
  const need = parsePermission(required)

  if (!need || need.resource === WILDCARD || need.action === WILDCARD) {
    // The requirement itself must be concrete — asking "is anything
    // allowed?" makes no sense and can never resolve to a grant.
    return false
  }

  if (!Array.isArray(granted)) {
    return false
  }

  return granted.some((entry) => {
    const have = parsePermission(entry)

    if (!have) {
      return false
    }

    const resourceOk = have.resource === WILDCARD || have.resource === need.resource
    const actionOk = have.action === WILDCARD || have.action === need.action

    return resourceOk && actionOk
  })
}

/**
 * As much of the access state as the decision needs. Structural on purpose
 * rather than importing `AclAccess` from the guard — the guard imports from
 * here, so a dependency the other way would be a cycle.
 */
export type AccessSnapshot = {
  active?: boolean
  superadmin?: boolean
  permissions?: readonly string[]
}

/**
 * Whether this access state lets a request for `required` through.
 *
 * This is the single place that decision is made. The guard uses it, and so
 * should your dashboard: a superadmin holds no role at all, so judging by
 * `permissions` alone makes the one account that passes everything look like
 * the one account with no access. Re-implementing the check in the UI is how
 * you end up hiding the roles screen from the very person meant to fix a
 * broken role setup.
 *
 * `required === null` means "a dashboard path we cannot classify": the escape
 * hatches (no verdict, ACL not active, superadmin) still apply, but there is
 * no concrete permission left to check, so anything else is denied.
 */
export function accessAllows(
  access: AccessSnapshot | null | undefined,
  required: string | null
): boolean {
  // No verdict, or ACL not configured yet => never lock the store owner out.
  // `superadmin` is the escape hatch for a role setup gone wrong.
  if (!access || !access.active || access.superadmin) {
    return true
  }

  if (required === null) {
    return false
  }

  return hasPermission(access.permissions ?? [], required)
}

/**
 * The permission a request requires. `null` means the request is out of
 * scope for access control (non-admin path, unclassified method, an
 * always-allowed route). `false` means an admin path we can't classify.
 */
export function permissionForRequest(
  method: string,
  path: string
): Permission | null | false {
  if (!isAdminPath(path)) {
    return null
  }

  const action = actionForMethod(method)

  if (!action) {
    return null
  }

  if (isAlwaysAllowed(method, path)) {
    return null
  }

  const resource = resourceForPath(path)

  if (!resource) {
    return false
  }

  return `${resource}:${action}`
}

/** Flat dictionary for the admin UI. */
export function permissionCatalog(): {
  label: string
  permissions: { value: Permission; resource: string; action: Action }[]
}[] {
  return RESOURCE_GROUPS.map((group) => ({
    label: group.label,
    permissions: group.resources.flatMap((resource) =>
      ACTIONS.map((action) => ({
        value: `${resource}:${action}`,
        resource,
        action,
      }))
    ),
  }))
}
