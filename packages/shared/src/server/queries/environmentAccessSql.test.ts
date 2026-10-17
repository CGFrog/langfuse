import { Prisma } from "@prisma/client";
import { describe, expect, it } from "vitest";

import {
  compileEnvironmentAccess,
  toEnvironmentDecisionList,
} from "../../features/rbac/environmentAccess";
import { EnvironmentAccessFilter } from "./clickhouse-sql/clickhouse-filter";
import { environmentAccessPrismaSql } from "./environmentAccessPrisma";

// Only staging and dev-* are readable; internal environments stay hidden.
const allowlist = toEnvironmentDecisionList(
  compileEnvironmentAccess("MEMBER", [
    { pattern: "*", role: "NONE" },
    { pattern: "staging", role: "VIEWER" },
    { pattern: "dev_*", role: "VIEWER" },
  ]),
  "traces:read",
);

describe("EnvironmentAccessFilter", () => {
  it("renders the decision list over the prefixed column", () => {
    const { query, params } = new EnvironmentAccessFilter({
      decisions: allowlist,
      clickhouseTable: "traces",
      tablePrefix: "t",
    }).apply();
    const names = Object.keys(params);
    expect(names).toHaveLength(3);
    expect(Object.values(params)).toEqual(["langfuse", "staging", "dev\\_%"]);
    expect(query).toBe(
      `(NOT (startsWith(t.environment, {${names[0]}: String})) AND (t.environment = {${names[1]}: String} OR t.environment LIKE {${names[2]}: String}))`,
    );
  });

  it("renders constants as trivially true or false conditions", () => {
    const render = (allow: boolean) =>
      new EnvironmentAccessFilter({
        decisions: { kind: "constant", allow },
        clickhouseTable: "scores",
      }).apply();
    expect(render(true)).toEqual({ query: "1 = 1", params: {} });
    expect(render(false)).toEqual({ query: "1 = 0", params: {} });
  });
});

describe("environmentAccessPrismaSql", () => {
  it("renders the decision list with bound values", () => {
    const sql = environmentAccessPrismaSql(
      allowlist,
      Prisma.raw(`"environment"`),
    );
    expect(sql.text).toBe(
      `(NOT ("environment" LIKE $1) AND ("environment" = $2 OR "environment" LIKE $3))`,
    );
    expect(sql.values).toEqual(["langfuse%", "staging", "dev\\_%"]);
  });
});
