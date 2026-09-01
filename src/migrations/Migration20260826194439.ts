import { Migration } from "@medusajs/framework/mikro-orm/migrations";

export class Migration20260826194439 extends Migration {

  override async up(): Promise<void> {
    this.addSql(`alter table if exists "acl_user_role" drop constraint if exists "acl_user_role_user_id_role_id_unique";`);
    this.addSql(`alter table if exists "acl_role" drop constraint if exists "acl_role_slug_unique";`);
    this.addSql(`create table if not exists "acl_role" ("id" text not null, "name" text not null, "slug" text not null, "description" text null, "permissions" jsonb null, "created_at" timestamptz not null default now(), "updated_at" timestamptz not null default now(), "deleted_at" timestamptz null, constraint "acl_role_pkey" primary key ("id"));`);
    this.addSql(`CREATE UNIQUE INDEX IF NOT EXISTS "IDX_acl_role_slug_unique" ON "acl_role" ("slug") WHERE deleted_at IS NULL;`);
    this.addSql(`CREATE INDEX IF NOT EXISTS "IDX_acl_role_deleted_at" ON "acl_role" ("deleted_at") WHERE deleted_at IS NULL;`);

    this.addSql(`create table if not exists "acl_user_role" ("id" text not null, "user_id" text not null, "role_id" text not null, "created_at" timestamptz not null default now(), "updated_at" timestamptz not null default now(), "deleted_at" timestamptz null, constraint "acl_user_role_pkey" primary key ("id"));`);
    this.addSql(`CREATE INDEX IF NOT EXISTS "IDX_acl_user_role_deleted_at" ON "acl_user_role" ("deleted_at") WHERE deleted_at IS NULL;`);
    this.addSql(`CREATE UNIQUE INDEX IF NOT EXISTS "IDX_acl_user_role_user_id_role_id_unique" ON "acl_user_role" ("user_id", "role_id") WHERE deleted_at IS NULL;`);
  }

  override async down(): Promise<void> {
    this.addSql(`drop table if exists "acl_role" cascade;`);

    this.addSql(`drop table if exists "acl_user_role" cascade;`);
  }

}
