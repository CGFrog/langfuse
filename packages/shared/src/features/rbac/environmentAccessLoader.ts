import type { Cluster, Redis } from "ioredis";
import { z } from "zod";

import { prisma as defaultPrisma, SystemRole, type Prisma } from "../../db";
import { env } from "../../env";
import { logger } from "../../server/logger";
import { redis as defaultRedis, safeMultiDel } from "../../server/redis/redis";
import {
  compileEnvironmentAccess,
  isUnrestrictableRole,
  type EnvironmentAccess,
  type EnvironmentGrant,
} from "./environmentAccess";
import { type PrincipalId } from "./types";

type LoaderDeps = {
  prisma: Prisma.TransactionClient;
  redis: Redis | Cluster | null;
};

const defaultDeps = (): LoaderDeps => ({
  prisma: defaultPrisma,
  redis: defaultRedis,
});

const CachedGrants = z.array(
  z.object({ pattern: z.string(), role: z.enum(SystemRole) }),
);

const cacheKey = (projectId: string, principalId: PrincipalId) =>
  `env-grants:v1:${projectId}:${principalId}`;

const cacheEnabled = (redis: LoaderDeps["redis"]) =>
  Boolean(redis) && env.LANGFUSE_CACHE_ENVIRONMENT_GRANTS_ENABLED === "true";

/** getEnvironmentGrantsForPrincipal loads a principal's stored grants in one project. */
export async function getEnvironmentGrantsForPrincipal(
  tx: Prisma.TransactionClient,
  projectId: string,
  principalId: PrincipalId,
): Promise<EnvironmentGrant[]> {
  const rows = await tx.environmentRoleGrant.findMany({
    where: { projectId, principalId },
    select: { pattern: true, systemRole: true },
  });
  return rows.map((row) => ({ pattern: row.pattern, role: row.systemRole }));
}

async function readCachedGrants(
  redis: Redis | Cluster,
  key: string,
): Promise<EnvironmentGrant[] | null> {
  try {
    // Plain GET rather than GETEX: a sliding TTL would keep revoked grants alive.
    const raw = await redis.get(key);
    if (raw === null) return null;
    const parsed = CachedGrants.safeParse(JSON.parse(raw));
    if (parsed.success) return parsed.data;
    await redis.del(key);
  } catch (error) {
    logger.error("Failed to read environment grants from cache", error);
  }
  return null;
}

async function writeCachedGrants(
  redis: Redis | Cluster,
  key: string,
  grants: EnvironmentGrant[],
): Promise<void> {
  try {
    await redis.set(
      key,
      JSON.stringify(grants),
      "EX",
      env.LANGFUSE_CACHE_ENVIRONMENT_GRANTS_TTL_SECONDS,
    );
  } catch (error) {
    logger.error("Failed to write environment grants to cache", error);
  }
}

/**
 * loadEnvironmentAccess compiles a principal's environment access within one
 * project. Grants are cached raw, including an empty list, because the base
 * role is resolved separately and may change independently. A cache failure
 * falls back to the database, never to unrestricted access.
 */
export async function loadEnvironmentAccess(
  params: {
    projectId: string;
    principalId: PrincipalId;
    baseRole: SystemRole;
  },
  deps: LoaderDeps = defaultDeps(),
): Promise<EnvironmentAccess> {
  if (isUnrestrictableRole(params.baseRole)) return { kind: "unrestricted" };

  const key = cacheKey(params.projectId, params.principalId);
  const redis = cacheEnabled(deps.redis) ? deps.redis : null;

  let grants = redis ? await readCachedGrants(redis, key) : null;
  if (grants === null) {
    grants = await getEnvironmentGrantsForPrincipal(
      deps.prisma,
      params.projectId,
      params.principalId,
    );
    if (redis) await writeCachedGrants(redis, key, grants);
  }
  return compileEnvironmentAccess(params.baseRole, grants);
}

/** invalidateEnvironmentGrants drops cached grants; call it after the writing transaction commits. */
export async function invalidateEnvironmentGrants(
  projectId: string,
  principalIds: PrincipalId[],
  redis: Redis | Cluster | null = defaultRedis,
): Promise<void> {
  try {
    await safeMultiDel(
      redis,
      principalIds.map((principalId) => cacheKey(projectId, principalId)),
    );
  } catch (error) {
    logger.error("Failed to invalidate cached environment grants", error);
  }
}
