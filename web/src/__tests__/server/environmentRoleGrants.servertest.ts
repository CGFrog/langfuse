import { v4 } from "uuid";
import { describe, expect, it } from "vitest";

import { InvalidRequestError } from "@langfuse/shared";
import { prisma } from "@langfuse/shared/src/db";
import { createOrgProjectAndApiKey, redis } from "@langfuse/shared/src/server";
import {
  getEnvironmentGrantsForPrincipal,
  loadEnvironmentAccess,
  setEnvironmentGrants,
  transferEnvironmentRoleGrants,
} from "@langfuse/shared/rbac/server";
import { ApiKeyId, UserId, type PrincipalId } from "@langfuse/shared/rbac";

const setupProjectWithMember = async () => {
  const { projectId, orgId, publicKey } = await createOrgProjectAndApiKey();
  const user = await prisma.user.create({
    data: { name: v4(), email: `${v4()}@example.com` },
  });
  await prisma.organizationMembership.create({
    data: { orgId, userId: user.id, role: "MEMBER" },
  });
  const apiKey = await prisma.apiKey.findUniqueOrThrow({
    where: { publicKey },
    select: { id: true },
  });
  return {
    orgId,
    projectId,
    userPrincipal: UserId(user.id),
    keyPrincipal: ApiKeyId(apiKey.id),
  };
};

/** Counts grant lookups so cache hits are observable without mocking. */
const countingPrisma = () => {
  let lookups = 0;
  const client = {
    environmentRoleGrant: {
      findMany: (
        args: Parameters<typeof prisma.environmentRoleGrant.findMany>[0],
      ) => {
        lookups++;
        return prisma.environmentRoleGrant.findMany(args);
      },
    },
  } as unknown as typeof prisma;
  return { client, lookups: () => lookups };
};

describe("setEnvironmentGrants", () => {
  it("normalizes patterns and replaces the full rule set", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();

    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: userPrincipal,
      grants: [
        { pattern: "Dev-**", role: "VIEWER" },
        { pattern: "production", role: "NONE" },
      ],
    });
    expect(
      await getEnvironmentGrantsForPrincipal(prisma, projectId, userPrincipal),
    ).toEqual(
      expect.arrayContaining([
        { pattern: "dev-*", role: "VIEWER" },
        { pattern: "production", role: "NONE" },
      ]),
    );

    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: userPrincipal,
      grants: [{ pattern: "*", role: "VIEWER" }],
    });
    expect(
      await getEnvironmentGrantsForPrincipal(prisma, projectId, userPrincipal),
    ).toEqual([{ pattern: "*", role: "VIEWER" }]);
  });

  it.each([
    {
      name: "duplicate patterns after normalization",
      grants: [
        { pattern: "dev-*", role: "VIEWER" as const },
        { pattern: "DEV-*", role: "NONE" as const },
      ],
    },
    {
      name: "a reserved prefix without a hyphen",
      grants: [{ pattern: "langfuse_x", role: "VIEWER" as const }],
    },
    {
      name: "a user role above MEMBER",
      grants: [{ pattern: "staging", role: "ADMIN" as const }],
    },
    {
      name: "an api-key role for a user",
      grants: [{ pattern: "staging", role: "INGEST" as const }],
    },
  ])("rejects $name for a user", async ({ grants }) => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    await expect(
      setEnvironmentGrants(prisma, {
        orgId,
        projectId,
        principalId: userPrincipal,
        grants,
      }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it("accepts project api-key roles below ADMIN and rejects ADMIN", async () => {
    const { orgId, projectId, keyPrincipal } = await setupProjectWithMember();
    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: keyPrincipal,
      grants: [
        { pattern: "dev-*", role: "INGEST" },
        { pattern: "production", role: "NONE" },
      ],
    });
    await expect(
      setEnvironmentGrants(prisma, {
        orgId,
        projectId,
        principalId: keyPrincipal,
        grants: [{ pattern: "dev-*", role: "ADMIN" }],
      }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });

  it("rejects principals outside the project or organization", async () => {
    const a = await setupProjectWithMember();
    const b = await setupProjectWithMember();
    const grants = [{ pattern: "*", role: "NONE" as const }];

    await expect(
      setEnvironmentGrants(prisma, {
        orgId: a.orgId,
        projectId: a.projectId,
        principalId: b.keyPrincipal,
        grants,
      }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(
      setEnvironmentGrants(prisma, {
        orgId: a.orgId,
        projectId: a.projectId,
        principalId: b.userPrincipal,
        grants,
      }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
    await expect(
      setEnvironmentGrants(prisma, {
        orgId: b.orgId,
        projectId: a.projectId,
        principalId: a.userPrincipal,
        grants,
      }),
    ).rejects.toBeInstanceOf(InvalidRequestError);
  });
});

describe("environment_role_grants constraints", () => {
  it("rejects a principal id that disagrees with its foreign key", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    await expect(
      prisma.environmentRoleGrant.create({
        data: {
          orgId,
          projectId,
          principalId: `user/${v4()}`,
          userId: userPrincipal.slice("user/".length),
          pattern: "staging",
          systemRole: "VIEWER",
        },
      }),
    ).rejects.toThrow(/check constraint/);
  });

  it("rejects a pattern outside the allowed alphabet", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    await expect(
      prisma.environmentRoleGrant.create({
        data: {
          orgId,
          projectId,
          principalId: userPrincipal,
          userId: userPrincipal.slice("user/".length),
          pattern: "Prod%",
          systemRole: "VIEWER",
        },
      }),
    ).rejects.toThrow(/check constraint/);
  });

  it("cascades when the user or api key is deleted", async () => {
    const { orgId, projectId, userPrincipal, keyPrincipal } =
      await setupProjectWithMember();
    for (const principalId of [userPrincipal, keyPrincipal]) {
      await setEnvironmentGrants(prisma, {
        orgId,
        projectId,
        principalId,
        grants: [{ pattern: "*", role: "NONE" }],
      });
    }
    await prisma.user.delete({
      where: { id: userPrincipal.slice("user/".length) },
    });
    await prisma.apiKey.delete({
      where: { id: keyPrincipal.slice("apiKey/".length) },
    });
    expect(
      await prisma.environmentRoleGrant.count({ where: { projectId } }),
    ).toBe(0);
  });
});

describe("transferEnvironmentRoleGrants", () => {
  it("moves api-key grants and drops user grants", async () => {
    const { orgId, projectId, userPrincipal, keyPrincipal } =
      await setupProjectWithMember();
    for (const principalId of [userPrincipal, keyPrincipal]) {
      await setEnvironmentGrants(prisma, {
        orgId,
        projectId,
        principalId,
        grants: [{ pattern: "*", role: "NONE" }],
      });
    }
    const target = await prisma.organization.create({ data: { name: v4() } });

    const dropped = await prisma.$transaction(async (tx) => {
      await tx.project.update({
        where: { id: projectId },
        data: { orgId: target.id },
      });
      return await transferEnvironmentRoleGrants(tx, projectId, target.id);
    });

    expect(dropped).toEqual([userPrincipal]);
    const remaining = await prisma.environmentRoleGrant.findMany({
      where: { projectId },
    });
    expect(remaining).toHaveLength(1);
    expect(remaining[0]).toMatchObject({
      principalId: keyPrincipal,
      orgId: target.id,
    });
  });
});

describe("loadEnvironmentAccess", () => {
  it("is unrestricted without grants and for OWNER or ADMIN", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    expect(
      await loadEnvironmentAccess({
        projectId,
        principalId: userPrincipal,
        baseRole: "MEMBER",
      }),
    ).toEqual({ kind: "unrestricted" });

    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: userPrincipal,
      grants: [{ pattern: "*", role: "NONE" }],
    });
    expect(
      await loadEnvironmentAccess({
        projectId,
        principalId: userPrincipal,
        baseRole: "ADMIN",
      }),
    ).toEqual({ kind: "unrestricted" });
    expect(
      await loadEnvironmentAccess({
        projectId,
        principalId: userPrincipal,
        baseRole: "MEMBER",
      }),
    ).toEqual({
      kind: "restricted",
      baseRole: "MEMBER",
      grants: [{ pattern: "*", role: "NONE" }],
    });
  });

  it("serves repeat loads from the cache and invalidates on write", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    const counting = countingPrisma();
    const load = () =>
      loadEnvironmentAccess(
        { projectId, principalId: userPrincipal, baseRole: "MEMBER" },
        { prisma: counting.client, redis },
      );

    await load();
    await load();
    expect(counting.lookups()).toBe(1);

    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: userPrincipal,
      grants: [{ pattern: "production", role: "VIEWER" }],
    });
    expect(await load()).toMatchObject({ kind: "restricted" });
    expect(counting.lookups()).toBe(2);
  });

  it("falls back to the database when the cache fails", async () => {
    const { orgId, projectId, userPrincipal } = await setupProjectWithMember();
    await setEnvironmentGrants(prisma, {
      orgId,
      projectId,
      principalId: userPrincipal,
      grants: [{ pattern: "*", role: "NONE" }],
    });
    const failing = {
      get: () => Promise.reject(new Error("redis down")),
      set: () => Promise.reject(new Error("redis down")),
    } as unknown as typeof redis;

    expect(
      await loadEnvironmentAccess(
        {
          projectId,
          principalId: userPrincipal as PrincipalId,
          baseRole: "MEMBER",
        },
        { prisma, redis: failing },
      ),
    ).toMatchObject({ kind: "restricted" });
  });
});
