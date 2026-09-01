# @ipsoftware/medusa-acl

Role-based access control for the Medusa v2 admin dashboard. A role is a
named list of permissions, an admin user gets one or more roles, and a guard
in the middleware chain checks on every request whether the sum of a user's
permissions covers what the request needs.

No dependency on Medusa core's own experimental RBAC (see [why not just use
that](#doesnt-medusa-already-have-this) below) — this is a small, self-contained
module you can drop into any Medusa v2 project.

## Install

```bash
npm install @ipsoftware/medusa-acl
```

### 1. Register the module

```ts
// medusa-config.ts
export default defineConfig({
  // ...
  modules: [
    {
      resolve: "@ipsoftware/medusa-acl",
      options: {
        // Checked on every admin request; the panel can fire off a dozen at
        // once for a single screen, so this avoids a database round trip
        // per check. Defaults to 30000.
        cacheTtlMs: 30000,
      },
    },
  ],
})
```

### 2. Run the migration

```bash
npx medusa db:migrate
```

This creates two tables, `acl_role` and `acl_user_role`. The migration ships
pre-built inside the package — you don't need to (and shouldn't) run
`medusa db:generate` for this module yourself.

### 3. Wire the guard into your middlewares

```ts
// src/api/middlewares.ts
import { defineMiddlewares } from "@medusajs/framework/http"
import {
  createAclGuard,
  createAccessResolver,
  parseSuperadminEmails,
} from "@ipsoftware/medusa-acl"

const aclGuard = createAclGuard(
  createAccessResolver({
    superadminEmails: parseSuperadminEmails(process.env.ACL_SUPERADMIN_EMAILS),
    cacheTtlMs: Number(process.env.ACL_CACHE_TTL_MS ?? 30000),
  })
)

export default defineMiddlewares({
  routes: [
    { matcher: "/admin/*", middlewares: [aclGuard as any] },
    // ...your other middleware entries
  ],
})
```

See `templates/middlewares.example.ts` in this package for a fuller example.

### 4. Add the admin API routes

Medusa's file-based router only picks up routes that physically live in
*your* project's `src/api` — a package in `node_modules` can't inject them.
Copy the route handlers from this package's `templates/api/admin/acl`
into your project's `src/api/admin/acl`, keeping the same folder layout:

```
src/api/admin/acl/
  me/route.ts
  permissions/route.ts
  roles/route.ts
  roles/[id]/route.ts
  users/route.ts
  users/[id]/route.ts
```

Each template file is a thin wrapper that imports the actual logic from
`@ipsoftware/medusa-acl` — you're copying a few lines of routing glue, not
duplicating the module.

### 5. Add the cleanup subscriber

Copy `templates/subscribers/user-deleted.ts` into your project's
`src/subscribers/`. Without it, deleting an admin user leaves orphaned role
assignments — and if a new user is later created with the same id, they'd
inherit someone else's permissions.

### 6. Set the emergency allowlist

```bash
# .env
ACL_SUPERADMIN_EMAILS=you@example.com
```

Do this **before** assigning anyone a role for the first time (see
[When enforcement kicks in](#when-enforcement-kicks-in)). Without it, a
misconfigured role setup has no way back in short of deleting rows by hand.

## Where the required permission comes from

From the path and HTTP method — not a manually maintained route list:

```
GET    /admin/products/prod_1/variants  ->  products:read
POST   /admin/products                  ->  products:write
DELETE /admin/orders/order_1            ->  orders:delete
```

The resource is the first path segment after `/admin`; the action follows
from the method (`GET`/`HEAD` → `read`, `POST`/`PUT`/`PATCH` → `write`,
`DELETE` → `delete`). This means **a route added tomorrow is guarded too** —
there's no spot to forget about. The tradeoff is granularity:
`products:write` covers everything under `/admin/products`, with no
distinction between a variant and a price.

Granted permissions can use wildcards: `*` (everything), `products:*` (a
whole resource), `*:read` (read access everywhere). An invalid entry — a
typo like `products:edytuj` — is **rejected on save**, so it can never give
the false impression that something was granted.

## When enforcement kicks in

Only after **the first role is assigned to anyone**. Installing the module,
or preparing roles, doesn't lock anything by itself — otherwise, deploying
this package would close the dashboard on the store owner, and half-finished
setup work (roles defined, nobody assigned yet) would lock everyone out.

From that point on, an account with no role gets only the baseline set:
`stores:read`, `currencies:read`, `regions:read`. Without them the dashboard
doesn't boot at all — so instead of a logged-in user facing a wall of
errors, they see an empty desk.

Always reachable, regardless of roles: `GET /admin/users/me` (without it the
dashboard logs itself out) and `GET /admin/acl/me` (the dashboard needs to
know what to hide).

## Escape hatches

1. `ACL_SUPERADMIN_EMAILS` — a comma-separated list of addresses. These
   accounts pass everything regardless of role. This is the only way back in
   once roles are configured so that nobody can fix them anymore.
2. Self-lockout protection: the API rejects a change that would leave the
   person making it without `acl:write` (editing their own role, deleting
   it, or making the very first assignment while holding no role themselves).
3. As a last resort, straight against the database — deleting every
   assignment turns ACL off entirely:
   ```bash
   psql "$DATABASE_URL" -c 'delete from acl_user_role;'
   ```
   (adjust the connection string/command for however your project connects
   to Postgres — e.g. `docker compose exec postgres psql -U ... -c '...'`
   if it runs in a container).

## What lives where

```
permissions/   the resource dictionary and all matching logic (no dependencies)
guard/         middleware: request -> decision
access/        glue: ACL module + user module (emergency list) -> decision
cache/         the TTL cache
self-lockout/  the "you can't lock yourself out" rule
models/        acl_role, acl_user_role
service.ts     reads, writes, cache invalidation
```

The first three directories **import nothing from `@medusajs/*`** — the
access decision is made there, so it's testable without a database or a
container. Tests sit in `__tests__` next to each of them
(`npm test`). `src/__tests__/service.spec.ts` is an integration test against
a real database; see the comment at the top of that file for how to run it
from inside a Medusa project.

## Gotcha: you have to write the 403 yourself

`MedusaError.Types.NOT_ALLOWED` **does not produce a 403** — the core's
error handling maps it, together with `INVALID_DATA`, to **400**. Permission
denials (the guard, and the `/admin/acl` routes) therefore write the response
directly: status 403 with body
`{ type: "not_allowed", message, required_permission }`. The dashboard uses
this shape to distinguish "you're not allowed to do that" from "the request
was malformed".

## Performance

Permissions are checked on every request, and the dashboard can fire off a
dozen at once. The result is cached in process memory for `cacheTtlMs`
(default 30s) and invalidated immediately on any role change, so an edit
takes effect right away rather than after the entry expires.

One thing to know when scaling horizontally: the cache is per-process, so
with several Medusa instances a role change reaches the others only once
their TTL expires.

## Doesn't Medusa already have this?

It does — since 2.14, but **behind the `MEDUSA_FF_RBAC` flag (off by
default) and with no UI**. Every route is tagged `@ignore`, so none of it
shows up in the docs. Here's how it works under the hood: the `@medusajs/rbac`
module (`rbac_role`, `rbac_policy` tables), a `user_rbac_role` link, the
`/admin/rbac/*` API, `policies` annotations on core routes, and a check in
`wrapWithPoliciesCheck`. Roles ride into the JWT at login time
(`generateJwtTokenForAuthIdentity` pulls a user's `rbac_roles` into
`app_metadata.roles`), and `check-permissions` compares them against each
route's policies.

Four reasons this package exists as a separate module anyway:

1. **No UI at all.** The `@medusajs/dashboard` package doesn't ship a single
   screen for roles — you're left with the raw `/admin/rbac/*` REST API.
2. **Roles are a snapshot from login time.** They live in the token and the
   session, so revoking someone's permissions only takes effect after they
   log in again. Here, a change applies immediately (the cache is
   invalidated on write).
3. **A startup trap.** `check-permissions` rejects a request when the role
   list is empty, and `/admin/rbac/*` routes carry policies themselves.
   Flipping the flag on a store where nobody has a role yet locks the
   dashboard for everyone — the first role then has to be inserted straight
   into the database. This package only activates on the first assignment,
   and ships its own `ACL_SUPERADMIN_EMAILS` escape hatch.
4. **Custom routes aren't guarded.** Core enforcement relies on a `policies`
   annotation on each route, and your own routes don't have one and won't
   unless someone adds it by hand. Here, the permission is derived from the
   path, so a new route is covered from the moment it exists.

This package never touches the `rbac_*` tables and never flips the flag, so
both mechanisms can coexist. If core ever ships a UI and graduates RBAC out
of experimental status, migrating means copying roles into `rbac_role` (the
data shape lines up: role → list of `resource:action`), flipping the flag,
and removing this package.

## License

MIT
