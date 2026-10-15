import { type Prisma, type PrismaClient, type SystemRole } from "../../db";
import { InvalidRequestError } from "../../errors";
import {
  EnvironmentPatternSchema,
  type EnvironmentGrant,
} from "./environmentAccess";
import { invalidateEnvironmentGrants } from "./environmentAccessLoader";
import { apiKeyRolesForScope } from "./systemRoleAccessRights";
import { hasApiKeyKind, untag, type PrincipalId, UserId } from "./types";

/** The most grants one principal may hold in one project. */
export const MAX_ENVIRONMENT_GRANTS_PER_PRINCIPAL = 50;

const USER_GRANT_ROLES: ReadonlySet<SystemRole> = new Set<SystemRole>([
  "NONE",
  "VIEWER",
  "MEMBER",
]);

/** API-key grants may use project-capable key roles below ADMIN, or NONE. */
const apiKeyGrantRoles = (): ReadonlySet<SystemRole> =>
  new Set<SystemRole>([
    "NONE",
    ...apiKeyRolesForScope("project").filter((role) => role !== "ADMIN"),
  ]);

/** normalizeGrants validates patterns and roles for a principal kind. */
function normalizeGrants(
  principalId: PrincipalId,
  grants: readonly EnvironmentGrant[],
): EnvironmentGrant[] {
  if (grants.length > MAX_ENVIRONMENT_GRANTS_PER_PRINCIPAL) {
    throw new InvalidRequestError(
      `At most ${MAX_ENVIRONMENT_GRANTS_PER_PRINCIPAL} environment grants are allowed`,
    );
  }
  const allowedRoles = hasApiKeyKind(principalId)
    ? apiKeyGrantRoles()
    : USER_GRANT_ROLES;
  const seen = new Set<string>();
  return grants.map((grant) => {
    const parsed = EnvironmentPatternSchema.safeParse(grant.pattern);
    if (!parsed.success) {
      throw new InvalidRequestError(
        `Invalid environment pattern "${grant.pattern}": ${parsed.error.issues[0]?.message}`,
      );
    }
    if (seen.has(parsed.data)) {
      throw new InvalidRequestError(
        `Duplicate environment pattern "${parsed.data}"`,
      );
    }
    seen.add(parsed.data);
    if (!allowedRoles.has(grant.role)) {
      throw new InvalidRequestError(
        `Role ${grant.role} cannot be granted per environment to this principal`,
      );
    }
    return { pattern: parsed.data, role: grant.role };
  });
}

/** validateTenancy holds project ownership stable and checks the principal belongs to it. */
async function validateTenancy(
  tx: Prisma.TransactionClient,
  orgId: string,
  projectId: string,
  principalId: PrincipalId,
): Promise<void> {
  const projects = await tx.$queryRaw<{ id: string }[]>`
    SELECT id FROM projects
    WHERE id = ${projectId} AND org_id = ${orgId}
    FOR SHARE
  `;
  if (projects.length === 0) {
    throw new InvalidRequestError("Project must belong to the organization");
  }
  if (hasApiKeyKind(principalId)) {
    const apiKey = await tx.apiKey.findUnique({
      where: { id: untag(principalId) },
      select: { projectId: true },
    });
    if (apiKey?.projectId !== projectId) {
      throw new InvalidRequestError("API key must belong to the project");
    }
    return;
  }
  const membership = await tx.organizationMembership.findUnique({
    where: { orgId_userId: { orgId, userId: untag(principalId) } },
    select: { id: true },
  });
  if (!membership) {
    throw new InvalidRequestError("User must be a member of the organization");
  }
}

/**
 * setEnvironmentGrants replaces a principal's full rule set in one project.
 * It owns its transaction so it can invalidate the cache after commit.
 */
export async function setEnvironmentGrants(
  prisma: PrismaClient,
  params: {
    orgId: string;
    projectId: string;
    principalId: PrincipalId;
    grants: readonly EnvironmentGrant[];
    createdByUserId?: string;
  },
): Promise<EnvironmentGrant[]> {
  const grants = normalizeGrants(params.principalId, params.grants);
  const principalFields = hasApiKeyKind(params.principalId)
    ? { apiKeyId: untag(params.principalId) }
    : { userId: untag(params.principalId) };

  await prisma.$transaction(async (tx) => {
    await validateTenancy(
      tx,
      params.orgId,
      params.projectId,
      params.principalId,
    );
    await tx.environmentRoleGrant.deleteMany({
      where: { projectId: params.projectId, principalId: params.principalId },
    });
    await tx.environmentRoleGrant.createMany({
      data: grants.map((grant) => ({
        orgId: params.orgId,
        projectId: params.projectId,
        principalId: params.principalId,
        ...principalFields,
        pattern: grant.pattern,
        systemRole: grant.role,
        createdByUserId: params.createdByUserId,
      })),
    });
  });
  await invalidateEnvironmentGrants(params.projectId, [params.principalId]);
  return grants;
}

/**
 * transferEnvironmentRoleGrants moves a transferred project's api-key grants to
 * the destination organization and drops its user grants, mirroring the
 * membership wipe. It returns the affected principals so the caller can
 * invalidate their cached grants after the transaction commits.
 */
export async function transferEnvironmentRoleGrants(
  tx: Prisma.TransactionClient,
  projectId: string,
  targetOrgId: string,
): Promise<PrincipalId[]> {
  const userGrants = await tx.environmentRoleGrant.findMany({
    where: { projectId, userId: { not: null } },
    select: { userId: true },
    distinct: ["userId"],
  });
  await tx.environmentRoleGrant.updateMany({
    where: { projectId, apiKeyId: { not: null } },
    data: { orgId: targetOrgId },
  });
  await tx.environmentRoleGrant.deleteMany({
    where: { projectId, userId: { not: null } },
  });
  return userGrants.flatMap((grant) =>
    grant.userId ? [UserId(grant.userId)] : [],
  );
}
