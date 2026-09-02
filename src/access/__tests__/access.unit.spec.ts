import { TtlCache } from "../../cache"
import { ACL_MODULE } from "../../const"
import {
  aclOptionsFromEnv,
  createAccessResolver,
  createSuperadminResolver,
  parseSuperadminEmails,
} from ".."

function makeReq(options: {
  actorId?: string
  access?: any
  user?: any
  onResolve?: (key: string) => void
}) {
  const aclService = {
    getAccessForUser: jest.fn(async () =>
      options.access ?? { active: true, permissions: ["products:read"] }
    ),
  }
  const userService = {
    retrieveUser: jest.fn(async () => {
      if (!options.user) {
        throw new Error("no such user")
      }
      return options.user
    }),
  }

  return {
    req: {
      method: "GET",
      originalUrl: "/admin/products",
      auth_context: options.actorId
        ? { actor_id: options.actorId, actor_type: "user" }
        : undefined,
      scope: {
        resolve: (key: string) => {
          options.onResolve?.(key)
          return key === ACL_MODULE ? aclService : userService
        },
      },
    } as any,
    aclService,
    userService,
  }
}

describe("parseSuperadminEmails", () => {
  it("reads a comma-separated list", () => {
    expect(parseSuperadminEmails("a@x.dev, B@X.DEV ,,")).toEqual([
      "a@x.dev",
      "b@x.dev",
    ])
  })

  it("an empty variable is an empty list, not a list with one empty entry", () => {
    expect(parseSuperadminEmails("")).toEqual([])
    expect(parseSuperadminEmails(undefined)).toEqual([])
    expect(parseSuperadminEmails(null)).toEqual([])
  })
})

describe("createAccessResolver", () => {
  it("returns null without an auth context", async () => {
    const resolver = createAccessResolver()
    const { req, aclService } = makeReq({})

    expect(await resolver(req)).toBeNull()
    expect(aclService.getAccessForUser).not.toHaveBeenCalled()
  })

  it("carries permissions over from the ACL module", async () => {
    const resolver = createAccessResolver()
    const { req, aclService } = makeReq({ actorId: "user_1" })

    expect(await resolver(req)).toEqual({
      active: true,
      permissions: ["products:read"],
      superadmin: false,
    })
    expect(aclService.getAccessForUser).toHaveBeenCalledWith("user_1")
  })

  it("without an allowlist it never asks about the user at all", async () => {
    const resolved: string[] = []
    const resolver = createAccessResolver()
    const { req, userService } = makeReq({
      actorId: "user_1",
      onResolve: (key) => resolved.push(key),
    })

    await resolver(req)

    expect(userService.retrieveUser).not.toHaveBeenCalled()
    expect(resolved).toEqual([ACL_MODULE])
  })

  it("recognizes an emergency-allowlist account by email", async () => {
    const resolver = createAccessResolver({
      superadminEmails: ["Boss@Shop.dev"],
    })
    const { req } = makeReq({
      actorId: "user_1",
      user: { email: "boss@shop.dev" },
    })

    expect((await resolver(req))?.superadmin).toBe(true)
  })

  it("a different address doesn't get a pass", async () => {
    const resolver = createAccessResolver({ superadminEmails: ["boss@shop.dev"] })
    const { req } = makeReq({
      actorId: "user_2",
      user: { email: "warehouse@shop.dev" },
    })

    expect((await resolver(req))?.superadmin).toBe(false)
  })

  it("an unreachable user module doesn't fail the request", async () => {
    const resolver = createAccessResolver({ superadminEmails: ["boss@shop.dev"] })
    const { req } = makeReq({ actorId: "user_3" })

    const access = await resolver(req)

    expect(access?.superadmin).toBe(false)
    expect(access?.active).toBe(true)
  })

  it("asks for the email once per cache window", async () => {
    let now = 0
    const cache = new TtlCache<string>(1000, () => now)
    const resolver = createAccessResolver({
      superadminEmails: ["boss@shop.dev"],
      emailCache: cache,
    })
    const { req, userService } = makeReq({
      actorId: "user_1",
      user: { email: "boss@shop.dev" },
    })

    await resolver(req)
    await resolver(req)
    expect(userService.retrieveUser).toHaveBeenCalledTimes(1)

    now += 1001
    await resolver(req)
    expect(userService.retrieveUser).toHaveBeenCalledTimes(2)
  })

  it("empty permissions from the module don't blow up on undefined", async () => {
    const resolver = createAccessResolver()
    const { req } = makeReq({
      actorId: "user_1",
      access: { active: true, permissions: undefined },
    })

    expect((await resolver(req))?.permissions).toEqual([])
  })
})

describe("createSuperadminResolver", () => {
  it("matches an account on the list, case-insensitively", async () => {
    const isSuperadmin = createSuperadminResolver({
      superadminEmails: ["Boss@Shop.test"],
    })
    const { req } = makeReq({ actorId: "user_1", user: { email: "BOSS@shop.TEST" } })

    expect(await isSuperadmin(req, "user_1")).toBe(true)
  })

  it("an account off the list is not a superadmin", async () => {
    const isSuperadmin = createSuperadminResolver({
      superadminEmails: ["boss@shop.test"],
    })
    const { req } = makeReq({ actorId: "user_1", user: { email: "someone@else.test" } })

    expect(await isSuperadmin(req, "user_1")).toBe(false)
  })

  it("an empty list never asks the user module for an email", async () => {
    const isSuperadmin = createSuperadminResolver()
    const { req, userService } = makeReq({
      actorId: "user_1",
      user: { email: "boss@shop.test" },
    })

    expect(await isSuperadmin(req, "user_1")).toBe(false)
    expect(userService.retrieveUser).not.toHaveBeenCalled()
  })

  it("an unknown user is not a superadmin, and not a crash", async () => {
    const isSuperadmin = createSuperadminResolver({
      superadminEmails: ["boss@shop.test"],
    })
    const { req } = makeReq({ actorId: "user_1" })

    expect(await isSuperadmin(req, "user_1")).toBe(false)
  })
})

describe("aclOptionsFromEnv", () => {
  it("reads the allowlist and the TTL from the environment", () => {
    expect(
      aclOptionsFromEnv({
        ACL_SUPERADMIN_EMAILS: "a@x.test, B@X.test",
        ACL_CACHE_TTL_MS: "5000",
      })
    ).toEqual({ superadminEmails: ["a@x.test", "b@x.test"], cacheTtlMs: 5000 })
  })

  it("with nothing set, an empty list and the default TTL", () => {
    const options = aclOptionsFromEnv({})

    expect(options.superadminEmails).toEqual([])
    expect(options.cacheTtlMs).toBe(30000)
  })

  it("the guard and an /admin/acl/me route agree on who is a superadmin", async () => {
    // The point of the fix: if these two read the environment separately and
    // drift apart, the dashboard hides the roles screen from an account the
    // API lets through.
    const env = { ACL_SUPERADMIN_EMAILS: "boss@shop.test" }
    const resolveAccess = createAccessResolver(aclOptionsFromEnv(env))
    const isSuperadmin = createSuperadminResolver(aclOptionsFromEnv(env))
    const { req } = makeReq({
      actorId: "user_1",
      user: { email: "boss@shop.test" },
      access: { active: true, permissions: [] },
    })

    expect((await resolveAccess(req))?.superadmin).toBe(true)
    expect(await isSuperadmin(req, "user_1")).toBe(true)
  })
})
