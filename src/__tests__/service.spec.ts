/**
 * Integration test — needs a real Postgres database and Medusa's test
 * container, so it can't run from this package's own repo in isolation.
 * Copy it into a Medusa project that has this package installed, adjust the
 * `resolve` path below to point at the package (or your local module
 * folder), and run it with `medusa test:integration:modules` (see
 * https://docs.medusajs.com/learn/advanced-development/testing).
 */
import { moduleIntegrationTestRunner } from "@medusajs/test-utils"
import { ACL_MODULE } from "../const"
import { Role } from "../models/role"
import { UserRole } from "../models/user-role"
import type AclModuleService from "../service"

jest.setTimeout(60_000)

// This suite hits a real database. It checks the things mocks can't: that
// the models and migrations agree with each other, and that the methods
// MedusaService generates are named the way the service assumes.
moduleIntegrationTestRunner<AclModuleService>({
  moduleName: ACL_MODULE,
  resolve: "@ipsoftware/medusa-acl",
  moduleModels: [Role, UserRole],
  moduleOptions: { cacheTtlMs: 0 },
  testSuite: ({ service }) => {
    describe("AclModuleService", () => {
      it("access control isn't in effect with no assignments", async () => {
        await service.saveRole({ name: "Warehouse", permissions: ["products:read"] })

        const access = await service.getAccessForUser("user_1")

        // Defining a role alone turns nothing on — otherwise preparing
        // roles would lock the dashboard mid-setup.
        expect(access.active).toBe(false)
        expect(access.permissions).toEqual([])
      })

      it("the first assignment turns on access control and grants permissions", async () => {
        const role = await service.saveRole({
          name: "Warehouse",
          permissions: ["products:read", "products:write"],
        })

        await service.setUserRoles("user_1", [role.id])
        const access = await service.getAccessForUser("user_1")

        expect(access.active).toBe(true)
        expect(access.permissions).toEqual(
          expect.arrayContaining(["products:read", "products:write"])
        )
        // The baseline set is always added, or the dashboard can't boot.
        expect(access.permissions).toEqual(expect.arrayContaining(["stores:read"]))
        expect(access.role_ids).toEqual([role.id])
      })

      it("once enabled, a roleless account gets only the baseline set", async () => {
        const role = await service.saveRole({ name: "Owner", permissions: ["*"] })
        await service.setUserRoles("user_1", [role.id])

        const access = await service.getAccessForUser("user_2")

        expect(access.active).toBe(true)
        expect(access.permissions).not.toContain("*")
        expect(access.permissions).toContain("stores:read")
      })

      it("filters out invalid permissions and builds a slug from the name", async () => {
        const role = await service.saveRole({
          name: "Order Handling",
          permissions: ["orders:read", "orders:edit", "ORDERS:read"],
        })

        expect(role.slug).toBe("order-handling")
        expect(role.permissions).toEqual(["orders:read"])
      })

      it("doesn't allow two roles with the same slug", async () => {
        await service.saveRole({ name: "Warehouse" })

        await expect(service.saveRole({ name: "warehouse" })).rejects.toThrow(
          /already exists/
        )
      })

      it("requires a name", async () => {
        await expect(service.saveRole({ name: "   " })).rejects.toThrow(/name/)
      })

      it("setting roles replaces the previous set", async () => {
        const a = await service.saveRole({ name: "A", permissions: ["orders:read"] })
        const b = await service.saveRole({ name: "B", permissions: ["products:read"] })

        await service.setUserRoles("user_1", [a.id, b.id])
        await service.setUserRoles("user_1", [b.id])

        const access = await service.getAccessForUser("user_1")

        expect(access.role_ids).toEqual([b.id])
        expect(access.permissions).toContain("products:read")
        expect(access.permissions).not.toContain("orders:read")
      })

      it("rejects assigning a role that doesn't exist", async () => {
        await expect(
          service.setUserRoles("user_1", ["aclrole_missing"])
        ).rejects.toThrow(/No such roles/)
      })

      it("removing a role takes its assignments with it", async () => {
        const role = await service.saveRole({ name: "Temporary" })
        await service.setUserRoles("user_1", [role.id])

        await service.removeRole(role.id)

        expect(await service.listUserRoles({ role_id: role.id })).toHaveLength(0)
        expect((await service.getAccessForUser("user_1")).active).toBe(false)
      })

      it("cleans up a deleted admin user's assignments", async () => {
        const role = await service.saveRole({ name: "Role" })
        await service.setUserRoles("user_1", [role.id])

        await service.removeUserAssignments("user_1")

        expect(await service.listUserRoles({ user_id: "user_1" })).toHaveLength(0)
      })

      it("a role's permission change is visible immediately", async () => {
        const role = await service.saveRole({ name: "Role", permissions: [] })
        await service.setUserRoles("user_1", [role.id])
        await service.getAccessForUser("user_1")

        await service.saveRole({
          id: role.id,
          name: "Role",
          permissions: ["orders:read"],
        })

        expect((await service.getAccessForUser("user_1")).permissions).toContain(
          "orders:read"
        )
      })

      it("the lockout snapshot sees roles and assignments", async () => {
        const role = await service.saveRole({
          name: "Owner",
          permissions: ["acl:write"],
        })
        await service.setUserRoles("user_1", [role.id])

        const snapshot = await service.getLockoutSnapshot("user_1")

        expect(snapshot.assignmentCount).toBe(1)
        expect(snapshot.actorRoleIds).toEqual([role.id])
        expect(snapshot.roles).toEqual([
          { id: role.id, permissions: ["acl:write"] },
        ])
      })
    })
  },
})
