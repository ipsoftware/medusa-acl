import type { Permission } from "./permissions"

export type AclModuleOptions = {
  /** Time-to-live for the permission cache (ms). 0 disables it. */
  cacheTtlMs?: number
}

export type RoleInput = {
  id?: string
  name: string
  slug?: string
  description?: string | null
  permissions?: string[]
}

export type RoleDTO = {
  id: string
  name: string
  slug: string
  description: string | null
  permissions: Permission[]
  created_at?: Date
  updated_at?: Date
}

export type UserAccess = {
  active: boolean
  permissions: Permission[]
  role_ids: string[]
}
