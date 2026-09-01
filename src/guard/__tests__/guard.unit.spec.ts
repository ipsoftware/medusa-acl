import { createAclGuard, requestPath, type AclAccess } from ".."

type Recorded = { status?: number; body?: any }

function makeRes(): { res: any; recorded: Recorded } {
  const recorded: Recorded = {}
  const res: any = {
    status(code: number) {
      recorded.status = code
      return res
    },
    json(body: any) {
      recorded.body = body
      return body
    },
  }
  return { res, recorded }
}

function makeReq(
  method: string,
  url: string,
  actorId: string | null = "user_1",
  actorType = "user"
): any {
  return {
    method,
    originalUrl: url,
    auth_context: actorId
      ? { actor_id: actorId, actor_type: actorType }
      : undefined,
    scope: { resolve: () => ({}) },
  }
}

const access = (partial: Partial<AclAccess> = {}): AclAccess => ({
  active: true,
  superadmin: false,
  permissions: [],
  ...partial,
})

describe("requestPath", () => {
  it("prefers originalUrl, since the middleware can be mounted below the root", () => {
    expect(
      requestPath({ method: "GET", originalUrl: "/admin/products", url: "/products" } as any)
    ).toBe("/admin/products")
    expect(requestPath({ method: "GET", url: "/admin/orders" } as any)).toBe(
      "/admin/orders"
    )
    expect(requestPath({ method: "GET" } as any)).toBe("")
  })
})

describe("createAclGuard", () => {
  it("lets non-admin requests through without asking about permissions", async () => {
    const resolve = jest.fn()
    const guard = createAclGuard(resolve)
    const next = jest.fn()

    await guard(makeReq("GET", "/store/products"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
    expect(resolve).not.toHaveBeenCalled()
  })

  it("lets CORS preflight OPTIONS through", async () => {
    const resolve = jest.fn()
    const guard = createAclGuard(resolve)
    const next = jest.fn()

    await guard(makeReq("OPTIONS", "/admin/products"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
    expect(resolve).not.toHaveBeenCalled()
  })

  it("doesn't fake a 403 when there's no auth context — that's the core's job", async () => {
    const resolve = jest.fn()
    const guard = createAclGuard(resolve)
    const next = jest.fn()
    const { res, recorded } = makeRes()

    await guard(makeReq("GET", "/admin/products", null), res, next)

    expect(next).toHaveBeenCalledWith()
    expect(recorded.status).toBeUndefined()
    expect(resolve).not.toHaveBeenCalled()
  })

  it("leaves other actor types alone (e.g. an API key)", async () => {
    const resolve = jest.fn()
    const guard = createAclGuard(resolve)
    const next = jest.fn()

    await guard(
      makeReq("GET", "/admin/products", "apk_1", "api-key"),
      makeRes().res,
      next
    )

    expect(next).toHaveBeenCalledWith()
    expect(resolve).not.toHaveBeenCalled()
  })

  it("lets everything through until someone has been assigned a role", async () => {
    const guard = createAclGuard(async () => access({ active: false }))
    const next = jest.fn()
    const { res, recorded } = makeRes()

    await guard(makeReq("DELETE", "/admin/orders/order_1"), res, next)

    expect(next).toHaveBeenCalledWith()
    expect(recorded.status).toBeUndefined()
  })

  it("lets an emergency-allowlist account through despite empty permissions", async () => {
    const guard = createAclGuard(async () =>
      access({ superadmin: true, permissions: [] })
    )
    const next = jest.fn()

    await guard(makeReq("DELETE", "/admin/products/prod_1"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
  })

  it("lets the request through when a role covers the required permission", async () => {
    const guard = createAclGuard(async () =>
      access({ permissions: ["products:read"] })
    )
    const next = jest.fn()

    await guard(makeReq("GET", "/admin/products?limit=20"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
  })

  it("denies with 403 and names the missing permission", async () => {
    const guard = createAclGuard(async () =>
      access({ permissions: ["products:read"] })
    )
    const next = jest.fn()
    const { res, recorded } = makeRes()

    await guard(makeReq("POST", "/admin/products"), res, next)

    expect(next).not.toHaveBeenCalled()
    expect(recorded.status).toBe(403)
    expect(recorded.body).toMatchObject({
      type: "not_allowed",
      required_permission: "products:write",
    })
  })

  it("a read permission doesn't grant write or delete", async () => {
    const guard = createAclGuard(async () =>
      access({ permissions: ["orders:read"] })
    )

    for (const method of ["POST", "DELETE"]) {
      const next = jest.fn()
      const { res, recorded } = makeRes()

      await guard(makeReq(method, "/admin/orders/order_1"), res, next)

      expect(next).not.toHaveBeenCalled()
      expect(recorded.status).toBe(403)
    }
  })

  it("denies on an admin path it can't classify", async () => {
    const warn = jest.fn()
    const guard = createAclGuard(async () => access({ permissions: ["*"] }), {
      warn,
    })
    const next = jest.fn()
    const { res, recorded } = makeRes()

    await guard(makeReq("GET", "/admin"), res, next)

    expect(next).not.toHaveBeenCalled()
    expect(recorded.status).toBe(403)
    expect(recorded.body.required_permission).toBeNull()
    expect(warn).toHaveBeenCalled()
  })

  it("doesn't ask about permissions on always-allowed routes", async () => {
    const resolve = jest.fn()
    const guard = createAclGuard(resolve)
    const next = jest.fn()

    await guard(makeReq("GET", "/admin/acl/me"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
    expect(resolve).not.toHaveBeenCalled()
  })

  it("stashes the result on the request so /admin/acl routes don't ask twice", async () => {
    const resolved = access({ permissions: ["acl:write"] })
    const guard = createAclGuard(async () => resolved)
    const req = makeReq("GET", "/admin/acl/roles")

    await guard(req, makeRes().res, jest.fn())

    expect(req.acl_access).toBe(resolved)
  })

  it("forwards a resolver error to error handling instead of swallowing it", async () => {
    const boom = new Error("database is down")
    const guard = createAclGuard(async () => {
      throw boom
    })
    const next = jest.fn()
    const { res, recorded } = makeRes()

    await guard(makeReq("GET", "/admin/products"), res, next)

    expect(next).toHaveBeenCalledWith(boom)
    expect(recorded.status).toBeUndefined()
  })

  it("a null resolution doesn't block the request", async () => {
    const guard = createAclGuard(async () => null)
    const next = jest.fn()

    await guard(makeReq("GET", "/admin/products"), makeRes().res, next)

    expect(next).toHaveBeenCalledWith()
  })
})
