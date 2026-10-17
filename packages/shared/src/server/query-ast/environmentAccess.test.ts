import { describe, expect, it } from "vitest";

import {
  compileEnvironmentAccess,
  toEnvironmentDecisionList,
  type EnvironmentDecisionList,
} from "../../features/rbac/environmentAccess";
import { compileClickhouseQuery } from "./compile";
import { getClickhouseKysely } from "./dialect";
import { QueryCompileError } from "./errors";
import { ENVIRONMENT_TABLES } from "./environmentAccess";

// Raw compiler output, so these run without a `clickhouse` binary.
const projectId = "p";

// VIEWER in production, NONE in secret-*, the project role elsewhere.
const restricted: EnvironmentDecisionList = toEnvironmentDecisionList(
  compileEnvironmentAccess("MEMBER", [
    { pattern: "secret-*", role: "NONE" },
    { pattern: "production", role: "VIEWER" },
  ]),
  "traces:read",
);

function compile(
  builder: Parameters<typeof compileClickhouseQuery>[0],
  environment?: EnvironmentDecisionList,
) {
  return compileClickhouseQuery(builder, projectId, { environment });
}

describe("environment access filtering", () => {
  it("covers every registry table with an environment column", () => {
    expect([...ENVIRONMENT_TABLES].sort()).toEqual([
      "events_core",
      "events_full",
      "observations",
      "scores",
      "traces",
    ]);
  });

  it("leaves SQL unchanged without a restriction", () => {
    const query = () =>
      getClickhouseKysely()
        .selectFrom("traces as t")
        .select("t.id")
        .where("t.id", "=", "x");
    expect(compile(query(), { kind: "constant", allow: true })).toEqual(
      compileClickhouseQuery(query(), projectId),
    );
  });

  it("prepends the predicate to WHERE, qualified by alias", () => {
    const { sql, params } = compile(
      getClickhouseKysely()
        .selectFrom("traces as t")
        .select("t.id")
        .where("t.id", "=", "x"),
      restricted,
    );
    expect(sql).toMatchInlineSnapshot(
      `"select t.id from traces as t where t.project_id = {p1:String} and (not (t.environment like {p2:String}) and (t.environment = {p3:String} or not (t.environment like {p4:String}))) and t.id = {p5:String}"`,
    );
    expect(params).toMatchInlineSnapshot(`
      {
        "p1": "p",
        "p2": "langfuse%",
        "p3": "production",
        "p4": "secret-%",
        "p5": "x",
      }
    `);
  });

  it("puts a joined table's predicate in its ON clause", () => {
    expect(
      compile(
        getClickhouseKysely()
          .selectFrom("traces as t")
          .innerJoin("scores as s", "s.trace_id", "t.id")
          .select(["t.id", "s.name"]),
        restricted,
      ).sql,
    ).toMatchInlineSnapshot(
      `"select t.id, s.name from traces as t inner join scores as s on s.trace_id = t.id and (not (s.environment like {p1:String}) and (s.environment = {p2:String} or not (s.environment like {p3:String}))) and s.project_id = {p4:String} where t.project_id = {p4:String} and (not (t.environment like {p1:String}) and (t.environment = {p2:String} or not (t.environment like {p3:String})))"`,
    );
  });

  it("filters a CTE body but not the CTE reference", () => {
    expect(
      compile(
        getClickhouseKysely()
          .with("recent", (db) =>
            db.selectFrom("traces").select(["id", "environment"]),
          )
          .selectFrom("recent")
          .select("recent.id"),
        restricted,
      ).sql,
    ).toMatchInlineSnapshot(
      `"with recent as (select id, environment from traces where project_id = {p1:String} and (not (traces.environment like {p2:String}) and (traces.environment = {p3:String} or not (traces.environment like {p4:String})))) select recent.id from recent"`,
    );
  });

  it("compiles a deny-all list to a false condition", () => {
    expect(
      compile(getClickhouseKysely().selectFrom("scores").select("id"), {
        kind: "constant",
        allow: false,
      }).sql,
    ).toMatchInlineSnapshot(
      `"select id from scores where project_id = {p1:String} and 1 = 0"`,
    );
  });

  it("rejects a RIGHT JOIN on a restricted select", () => {
    expect(() =>
      compile(
        getClickhouseKysely()
          .selectFrom("traces as t")
          .rightJoin("scores as s", "s.trace_id", "t.id")
          .select("t.id"),
        restricted,
      ),
    ).toThrow(QueryCompileError);
  });
});
