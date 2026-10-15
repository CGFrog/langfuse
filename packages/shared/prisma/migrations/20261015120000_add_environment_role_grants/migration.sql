-- CreateTable
CREATE TABLE "environment_role_grants" (
    "id" TEXT NOT NULL,
    "org_id" TEXT NOT NULL,
    "project_id" TEXT NOT NULL,
    "principal_id" TEXT NOT NULL,
    "user_id" TEXT,
    "api_key_id" TEXT,
    "pattern" TEXT NOT NULL,
    "system_role" "SystemRole" NOT NULL,
    "created_by_user_id" TEXT,
    "created_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updated_at" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,

    CONSTRAINT "environment_role_grants_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "environment_role_grants_principal_check" CHECK (
        ("user_id" IS NOT NULL AND "api_key_id" IS NULL AND "principal_id" = 'user/' || "user_id")
        OR
        ("user_id" IS NULL AND "api_key_id" IS NOT NULL AND "principal_id" = 'apiKey/' || "api_key_id")
    ),
    CONSTRAINT "environment_role_grants_pattern_check" CHECK (
        "pattern" ~ '^[a-z0-9_*-]{1,64}$'
    )
);

-- CreateIndex
CREATE INDEX "environment_role_grants_org_id_idx" ON "environment_role_grants"("org_id");

-- CreateIndex
CREATE INDEX "environment_role_grants_user_id_idx" ON "environment_role_grants"("user_id");

-- CreateIndex
CREATE INDEX "environment_role_grants_api_key_id_idx" ON "environment_role_grants"("api_key_id");

-- CreateIndex
CREATE UNIQUE INDEX "environment_role_grants_project_id_principal_id_pattern_key" ON "environment_role_grants"("project_id", "principal_id", "pattern");

-- AddForeignKey
ALTER TABLE "environment_role_grants" ADD CONSTRAINT "environment_role_grants_org_id_fkey" FOREIGN KEY ("org_id") REFERENCES "organizations"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "environment_role_grants" ADD CONSTRAINT "environment_role_grants_project_id_fkey" FOREIGN KEY ("project_id") REFERENCES "projects"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "environment_role_grants" ADD CONSTRAINT "environment_role_grants_user_id_fkey" FOREIGN KEY ("user_id") REFERENCES "users"("id") ON DELETE CASCADE ON UPDATE CASCADE;

-- AddForeignKey
ALTER TABLE "environment_role_grants" ADD CONSTRAINT "environment_role_grants_api_key_id_fkey" FOREIGN KEY ("api_key_id") REFERENCES "api_keys"("id") ON DELETE CASCADE ON UPDATE CASCADE;
