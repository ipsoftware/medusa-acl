import { Module } from "@medusajs/framework/utils"
import AclModuleService from "./service"
import { ACL_MODULE } from "./const"

export { ACL_MODULE }
export * from "./permissions"
export * from "./types"
export { createAclGuard } from "./guard"
export type {
  AclAccess,
  GuardRequest,
  GuardResponse,
  AccessResolver,
  GuardLogger,
} from "./guard"
export { createAccessResolver, parseSuperadminEmails } from "./access"
export type { AclServiceLike, CreateAccessResolverOptions } from "./access"
export { keepsAclControl, ACL_CONTROL_PERMISSION } from "./self-lockout"
export type { RoleLike, LockoutCheckInput } from "./self-lockout"
export { TtlCache } from "./cache"
export { Role } from "./models/role"
export { UserRole } from "./models/user-role"
export type { default as AclModuleService } from "./service"

export default Module(ACL_MODULE, {
  service: AclModuleService,
})
