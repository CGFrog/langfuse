import { v4 } from "uuid";
import { describe, expect, it } from "vitest";

import { Prisma, prisma, type SystemRole } from "@langfuse/shared/src/db";
import {
  createTrace,
  createTracesCh,
  EnvironmentAccessFilter,
  environmentAccessPrismaSql,
  queryClickhouse,
} from "@langfuse/shared/src/server";
import { compileClickhouseQuery } from "@langfuse/shared/src/server/query-ast/compile";
import { getClickhouseKysely } from "@langfuse/shared/src/server/query-ast/dialect";
import {
  compileEnvironmentAccess,
  EnvironmentPatternSchema,
  hasEnvironmentAccess,
  toEnvironmentDecisionList,
  type EnvironmentAccess,
  type EnvironmentGrant,
} from "@langfuse/shared/rbac";

// Environments chosen to separate exact, glob, `_` and internal handling.
const ENVIRONMENTS = [
  "default",
  "production",
  "staging",
  "dev",
  "dev-a",
  "dev_a",
  "devxa",
  "a_b",
  "aab",
  "a-b",
  "ab",
  "b",
  "secret-x",
  "x-secret",
  "langfuse-llm-as-a-judge",
  "langfuse-prompt-experiment",
  "langfuse-a_b",
];

const PATTERN_POOL = [
  "*",
  "production",
  "staging",
  "dev*",
  "dev-*",
  "dev_*",
  "a_b",
  "a*b",
  "*b",
  "*-*",
  "secret-*",
  "*secret*",
  "langfuse-*",
  "langfuse-a_*",
  "langfuse-llm-as-a-judge",
];

const ROLES: SystemRole[] = ["MEMBER", "VIEWER", "NONE"];

/** Park–Miller MINSTD; the product stays below 2^53, so arithmetic is exact. */
const seeded = (initial: number) => {
  let seed = initial;
  return () => {
    seed = (seed * 48271) % 2147483647;
    return seed / 2147483647;
  };
};

const randomAccessCases = (count: number): EnvironmentAccess[] => {
  const random = seeded(104729);
  const pick = <T>(items: readonly T[]): T =>
    items[Math.floor(random() * items.length)];
  return Array.from({ length: count }, () => {
    const grants = new Map<string, EnvironmentGrant>();
    const grantCount = 1 + Math.floor(random() * 4);
    for (let i = 0; i < grantCount; i++) {
      const pattern = EnvironmentPatternSchema.parse(pick(PATTERN_POOL));
      grants.set(pattern, { pattern, role: pick(ROLES) });
    }
    return compileEnvironmentAccess(pick(["MEMBER", "VIEWER"] as const), [
      ...grants.values(),
    ]);
  });
};

const expectedVisible = (access: EnvironmentAccess) =>
  ENVIRONMENTS.filter((environment) =>
    hasEnvironmentAccess(access, environment, "traces:read"),
  ).sort();

const CASES = randomAccessCases(40);

describe("environment access SQL parity with the resolver", () => {
  it("ClickHouse filter", async () => {
    for (const access of CASES) {
      const filter = new EnvironmentAccessFilter({
        decisions: toEnvironmentDecisionList(access, "traces:read"),
        clickhouseTable: "traces",
      }).apply();
      const rows = await queryClickhouse<{ environment: string }>({
        query: `
          SELECT environment
          FROM (SELECT arrayJoin({environments: Array(String)}) AS environment)
          WHERE ${filter.query}
        `,
        params: { ...filter.params, environments: ENVIRONMENTS },
      });
      expect(
        rows.map((row) => row.environment).sort(),
        JSON.stringify(access),
      ).toEqual(expectedVisible(access));
    }
  });

  it("Postgres fragment", async () => {
    for (const access of CASES) {
      const predicate = environmentAccessPrismaSql(
        toEnvironmentDecisionList(access, "traces:read"),
        Prisma.raw("environment"),
      );
      const rows = await prisma.$queryRaw<{ environment: string }[]>(
        Prisma.sql`
          SELECT environment
          FROM unnest(${ENVIRONMENTS}::text[]) AS t(environment)
          WHERE ${predicate}
        `,
      );
      expect(
        rows.map((row) => row.environment).sort(),
        JSON.stringify(access),
      ).toEqual(expectedVisible(access));
    }
  });

  it("query-AST plugin", async () => {
    const projectId = v4();
    await createTracesCh(
      ENVIRONMENTS.map((environment) =>
        createTrace({ project_id: projectId, environment }),
      ),
    );
    for (const access of CASES) {
      const { sql, params } = compileClickhouseQuery(
        getClickhouseKysely().selectFrom("traces as t").select("t.environment"),
        projectId,
        { environment: toEnvironmentDecisionList(access, "traces:read") },
      );
      const rows = await queryClickhouse<{ environment: string }>({
        query: sql,
        params,
      });
      expect(
        rows.map((row) => row.environment).sort(),
        JSON.stringify(access),
      ).toEqual(expectedVisible(access));
    }
  });
});
