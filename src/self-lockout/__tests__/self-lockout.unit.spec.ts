import { keepsAclControl } from ".."

const role = (id: string, permissions: unknown) => ({ id, permissions })

describe("keepsAclControl", () => {
  it("allows it when the actor retains acl:write", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["acl:write", "products:read"])],
        activeAfter: true,
      })
    ).toBe(true)
  })

  it("blocks revoking your own right to manage roles", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["products:read"])],
        activeAfter: true,
      })
    ).toBe(false)
  })

  it("honors wildcards", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["*"])],
        activeAfter: true,
      })
    ).toBe(true)
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["acl:*"])],
        activeAfter: true,
      })
    ).toBe(true)
    // A read-only wildcard isn't enough for write.
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["*:read"])],
        activeAfter: true,
      })
    ).toBe(false)
  })

  it("sums permissions across the actor's roles", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1", "r2"],
        rolesAfter: [role("r1", ["products:read"]), role("r2", ["acl:write"])],
        activeAfter: true,
      })
    ).toBe(true)
  })

  it("doesn't count permissions from someone else's role", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", ["products:read"]), role("r2", ["acl:write"])],
        activeAfter: true,
      })
    ).toBe(false)
  })

  it("doesn't block while access control isn't in effect yet", () => {
    // With zero assignments the guard lets everything through anyway —
    // there's nothing to lock.
    expect(
      keepsAclControl({
        actorRoleIds: [],
        rolesAfter: [role("r1", ["products:read"])],
        activeAfter: false,
      })
    ).toBe(true)
  })

  it("blocks a first assignment made by someone without their own role", () => {
    // Granting a role to someone else turns access control on for the
    // granter too.
    expect(
      keepsAclControl({
        actorRoleIds: [],
        rolesAfter: [role("r1", ["products:read"])],
        activeAfter: true,
      })
    ).toBe(false)
  })

  it("an emergency-allowlist account always passes", () => {
    expect(
      keepsAclControl({
        actorRoleIds: [],
        rolesAfter: [role("r1", ["products:read"])],
        activeAfter: true,
        isSuperadmin: true,
      })
    ).toBe(true)
  })

  it("tolerates roles with malformed permissions", () => {
    expect(
      keepsAclControl({
        actorRoleIds: ["r1"],
        rolesAfter: [role("r1", null)],
        activeAfter: true,
      })
    ).toBe(false)
  })
})
