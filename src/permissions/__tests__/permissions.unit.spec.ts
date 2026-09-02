import {
  ACTIONS,
  BASELINE_PERMISSIONS,
  accessAllows,
  actionForMethod,
  hasPermission,
  isAdminPath,
  isAlwaysAllowed,
  mergePermissions,
  normalizePermissions,
  parsePermission,
  permissionCatalog,
  permissionForRequest,
  resourceForPath,
} from ".."

describe("actionForMethod", () => {
  it.each([
    ["GET", "read"],
    ["get", "read"],
    ["HEAD", "read"],
    ["POST", "write"],
    ["PUT", "write"],
    ["PATCH", "write"],
    ["DELETE", "delete"],
  ])("%s -> %s", (method, expected) => {
    expect(actionForMethod(method)).toBe(expected)
  })

  it("does not classify methods we don't guard", () => {
    expect(actionForMethod("OPTIONS")).toBeNull()
    expect(actionForMethod("")).toBeNull()
  })
})

describe("resourceForPath", () => {
  it("takes the first segment after /admin", () => {
    expect(resourceForPath("/admin/products")).toBe("products")
    expect(resourceForPath("/admin/products/prod_1/variants")).toBe("products")
    expect(resourceForPath("/admin/product-categories/pcat_1")).toBe(
      "product-categories"
    )
  })

  it("strips query params and the hash fragment", () => {
    expect(resourceForPath("/admin/orders?limit=20&offset=0")).toBe("orders")
    expect(resourceForPath("/admin/orders#x")).toBe("orders")
  })

  it("returns null outside /admin and for paths without a resource", () => {
    expect(resourceForPath("/store/products")).toBeNull()
    expect(resourceForPath("/admin")).toBeNull()
    expect(resourceForPath("/admin/")).toBeNull()
    expect(resourceForPath("")).toBeNull()
  })

  it("doesn't fall for a wildcard smuggled into the path", () => {
    expect(resourceForPath("/admin/*")).toBeNull()
    expect(resourceForPath("/admin/../store")).toBeNull()
  })
})

describe("isAdminPath", () => {
  it("recognizes admin paths", () => {
    expect(isAdminPath("/admin")).toBe(true)
    expect(isAdminPath("/admin/products")).toBe(true)
    expect(isAdminPath("/store/products")).toBe(false)
    // A similar prefix isn't the same prefix.
    expect(isAdminPath("/administrators")).toBe(false)
  })
})

describe("isAlwaysAllowed", () => {
  it("lets through the routes the dashboard can't boot without", () => {
    expect(isAlwaysAllowed("GET", "/admin/users/me")).toBe(true)
    expect(isAlwaysAllowed("GET", "/admin/acl/me")).toBe(true)
    expect(isAlwaysAllowed("get", "/admin/users/me/")).toBe(true)
  })

  it("doesn't extend to other methods or neighboring routes", () => {
    expect(isAlwaysAllowed("POST", "/admin/users/me")).toBe(false)
    expect(isAlwaysAllowed("GET", "/admin/users")).toBe(false)
    expect(isAlwaysAllowed("GET", "/admin/users/me/roles")).toBe(false)
  })
})

describe("parsePermission", () => {
  it("accepts the full form, the resource shorthand, and the wildcard", () => {
    expect(parsePermission("products:write")).toEqual({
      resource: "products",
      action: "write",
    })
    expect(parsePermission("products")).toEqual({
      resource: "products",
      action: "*",
    })
    expect(parsePermission("*")).toEqual({ resource: "*", action: "*" })
    expect(parsePermission("*:read")).toEqual({ resource: "*", action: "read" })
  })

  it("normalizes casing and whitespace", () => {
    expect(parsePermission("  Products:WRITE ")).toEqual({
      resource: "products",
      action: "write",
    })
  })

  it("rejects garbage instead of guessing", () => {
    // A typo in the action must never turn into a silent "anything goes".
    expect(parsePermission("products:edit")).toBeNull()
    expect(parsePermission("products:read:extra")).toBeNull()
    expect(parsePermission("")).toBeNull()
    expect(parsePermission("   ")).toBeNull()
    expect(parsePermission(":read")).toBeNull()
    expect(parsePermission("pro ducts:read")).toBeNull()
    expect(parsePermission(undefined as unknown as string)).toBeNull()
  })
})

describe("normalizePermissions", () => {
  it("drops invalid entries and removes duplicates", () => {
    expect(
      normalizePermissions([
        "products:read",
        "PRODUCTS:read",
        "products:edit",
        42,
        null,
        "orders",
      ])
    ).toEqual(["orders:*", "products:read"])
  })

  it("collapses the full wildcard to a single entry", () => {
    expect(normalizePermissions(["*", "*:*"])).toEqual(["*"])
  })

  it("returns an empty list for anything that isn't a list", () => {
    expect(normalizePermissions(undefined)).toEqual([])
    expect(normalizePermissions("products:read")).toEqual([])
  })
})

describe("mergePermissions", () => {
  it("combines permissions from several roles and adds the baseline set", () => {
    const merged = mergePermissions([
      ["products:read", "products:write"],
      ["orders:read", "products:read"],
    ])

    expect(merged).toContain("products:write")
    expect(merged).toContain("orders:read")
    for (const baseline of BASELINE_PERMISSIONS) {
      expect(merged).toContain(baseline)
    }
    // No duplicates.
    expect(new Set(merged).size).toBe(merged.length)
  })

  it("a user with no roles gets only the baseline set", () => {
    expect(mergePermissions([])).toEqual([...BASELINE_PERMISSIONS].sort())
  })

  it("tolerates roles with empty or malformed permissions", () => {
    expect(mergePermissions([null, undefined, "nonsense"])).toEqual(
      [...BASELINE_PERMISSIONS].sort()
    )
  })
})

describe("hasPermission", () => {
  it("matches directly", () => {
    expect(hasPermission(["products:read"], "products:read")).toBe(true)
    expect(hasPermission(["products:read"], "products:write")).toBe(false)
    expect(hasPermission(["products:read"], "orders:read")).toBe(false)
  })

  it("honors wildcards on the granted side", () => {
    expect(hasPermission(["*"], "orders:delete")).toBe(true)
    expect(hasPermission(["products:*"], "products:delete")).toBe(true)
    expect(hasPermission(["products:*"], "orders:delete")).toBe(false)
    expect(hasPermission(["*:read"], "orders:read")).toBe(true)
    expect(hasPermission(["*:read"], "orders:write")).toBe(false)
  })

  it("never grants access to a vague question", () => {
    // "Is anything allowed?" isn't a real access question.
    expect(hasPermission(["*"], "*")).toBe(false)
    expect(hasPermission(["*"], "products:*")).toBe(false)
    expect(hasPermission(["*"], "products:edit")).toBe(false)
  })

  it("tolerates garbage on the granted side", () => {
    expect(hasPermission(["products:edit", "products:read"], "products:read")).toBe(
      true
    )
    expect(hasPermission([undefined as any, 1 as any], "products:read")).toBe(
      false
    )
    expect(hasPermission(undefined as any, "products:read")).toBe(false)
  })
})

describe("permissionForRequest", () => {
  it("combines the resource with the action", () => {
    expect(permissionForRequest("GET", "/admin/products")).toBe("products:read")
    expect(permissionForRequest("POST", "/admin/products/prod_1")).toBe(
      "products:write"
    )
    expect(permissionForRequest("DELETE", "/admin/orders/order_1")).toBe(
      "orders:delete"
    )
  })

  it("returns null outside the scope of access control", () => {
    expect(permissionForRequest("GET", "/store/products")).toBeNull()
    expect(permissionForRequest("OPTIONS", "/admin/products")).toBeNull()
    expect(permissionForRequest("GET", "/admin/users/me")).toBeNull()
  })

  it("returns false for an admin path with no recognized resource", () => {
    // False means "don't know" here — the guard is expected to deny.
    expect(permissionForRequest("GET", "/admin")).toBe(false)
    expect(permissionForRequest("GET", "/admin/")).toBe(false)
  })
})

describe("permissionCatalog", () => {
  it("gives every resource a full set of actions", () => {
    const groups = permissionCatalog()

    expect(groups.length).toBeGreaterThan(0)

    for (const group of groups) {
      expect(group.permissions.length % ACTIONS.length).toBe(0)
      for (const permission of group.permissions) {
        expect(parsePermission(permission.value)).not.toBeNull()
      }
    }
  })

  it("includes the acl resource — otherwise nobody could ever be granted role management", () => {
    const values = permissionCatalog().flatMap((group) =>
      group.permissions.map((permission) => permission.value)
    )

    expect(values).toContain("acl:write")
  })
})

describe("accessAllows", () => {
  const access = (partial: Record<string, unknown> = {}) => ({
    active: true,
    superadmin: false,
    permissions: [] as string[],
    ...partial,
  })

  it("lets a superadmin through even though they hold no role", () => {
    // An account on ACL_SUPERADMIN_EMAILS never gets a role assignment, so by
    // permissions alone it looks like an account with no access. A dashboard
    // judging by permission strings hides the roles screen from the one person
    // meant to repair a broken role setup.
    const superadmin = access({
      superadmin: true,
      permissions: ["stores:read", "currencies:read", "regions:read"],
    })

    expect(accessAllows(superadmin, "acl:write")).toBe(true)
    expect(accessAllows(superadmin, null)).toBe(true)
  })

  it("lets everything through until somebody is assigned a role", () => {
    expect(accessAllows(access({ active: false }), "acl:write")).toBe(true)
  })

  it("no verdict does not lock the dashboard", () => {
    expect(accessAllows(null, "acl:write")).toBe(true)
    expect(accessAllows(undefined, "acl:write")).toBe(true)
  })

  it("honours wildcards, not just literal entries", () => {
    expect(accessAllows(access({ permissions: ["*"] }), "acl:write")).toBe(true)
    expect(accessAllows(access({ permissions: ["acl:*"] }), "acl:write")).toBe(true)
    // The one a literal `includes()` check in a dashboard would miss.
    expect(accessAllows(access({ permissions: ["*:write"] }), "acl:write")).toBe(true)
  })

  it("denies without cover — read alone is not write", () => {
    expect(accessAllows(access({ permissions: ["acl:read"] }), "acl:write")).toBe(false)
    expect(
      accessAllows(access({ permissions: ["products:write"] }), "acl:write")
    ).toBe(false)
  })

  it("an unclassifiable path passes only through an escape hatch", () => {
    expect(accessAllows(access({ permissions: ["*"] }), null)).toBe(false)
    expect(accessAllows(access({ active: false }), null)).toBe(true)
  })

  it("a missing permissions field does not blow up on undefined", () => {
    expect(accessAllows({ active: true }, "acl:write")).toBe(false)
  })
})
