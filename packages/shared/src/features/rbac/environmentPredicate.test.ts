import { describe, expect, it } from "vitest";
import { type SystemRole } from "../../db";
import { globToLikePattern } from "../../server/utils/sqlLike";
import {
  compileEnvironmentAccess,
  EnvironmentPatternSchema,
  hasEnvironmentAccess,
  toEnvironmentDecisionList,
  type EnvironmentGrant,
} from "./environmentAccess";
import {
  toEnvironmentPredicate,
  type EnvironmentPredicate,
} from "./environmentPredicate";
import { type ProjectAction } from "./systemRoleAccessRights";

/** SQL LIKE with `\` escapes, by dynamic programming over pattern tokens. */
const sqlLike = (pattern: string, value: string): boolean => {
  const tokens: { kind: "any" | "one" | "lit"; char?: string }[] = [];
  for (let i = 0; i < pattern.length; i++) {
    const c = pattern[i];
    if (c === "\\") tokens.push({ kind: "lit", char: pattern[++i] });
    else if (c === "%") tokens.push({ kind: "any" });
    else if (c === "_") tokens.push({ kind: "one" });
    else tokens.push({ kind: "lit", char: c });
  }
  let prev = Array<boolean>(value.length + 1).fill(false);
  prev[0] = true;
  for (const token of tokens) {
    const cur = Array<boolean>(value.length + 1).fill(false);
    cur[0] = token.kind === "any" && prev[0];
    for (let j = 1; j <= value.length; j++) {
      cur[j] =
        token.kind === "any"
          ? prev[j] || cur[j - 1]
          : prev[j - 1] &&
            (token.kind === "one" || token.char === value[j - 1]);
    }
    prev = cur;
  }
  return prev[value.length];
};

/** Evaluates the predicate the way the SQL renderers express it. */
const evaluate = (node: EnvironmentPredicate, environment: string): boolean => {
  switch (node.kind) {
    case "const":
      return node.value;
    case "eq":
      return environment === node.value;
    case "glob":
      return sqlLike(globToLikePattern(node.pattern), environment);
    case "internal":
      return sqlLike("langfuse%", environment);
    case "not":
      return !evaluate(node.arg, environment);
    case "and":
      return node.args.every((arg) => evaluate(arg, environment));
    case "or":
      return node.args.some((arg) => evaluate(arg, environment));
  }
};

const predicateFor = (
  baseRole: SystemRole,
  grants: EnvironmentGrant[],
  action: ProjectAction = "traces:read",
) =>
  toEnvironmentPredicate(
    toEnvironmentDecisionList(
      compileEnvironmentAccess(baseRole, grants),
      action,
    ),
  );

describe("toEnvironmentPredicate", () => {
  it("is constant for unrestricted access", () => {
    expect(predicateFor("MEMBER", [])).toEqual({ kind: "const", value: true });
  });

  it("folds an allowlist into public-only matches", () => {
    expect(
      predicateFor("MEMBER", [
        { pattern: "*", role: "NONE" },
        { pattern: "staging", role: "VIEWER" },
        { pattern: "dev-*", role: "VIEWER" },
      ]),
    ).toEqual({
      kind: "and",
      args: [
        { kind: "not", arg: { kind: "internal" } },
        {
          kind: "or",
          args: [
            { kind: "eq", value: "staging" },
            { kind: "glob", pattern: "dev-*" },
          ],
        },
      ],
    });
  });

  it("keeps internal grants in their own branch", () => {
    expect(
      predicateFor("MEMBER", [
        { pattern: "production", role: "NONE" },
        { pattern: "langfuse-*", role: "VIEWER" },
      ]),
    ).toEqual({
      kind: "or",
      args: [
        {
          kind: "and",
          args: [{ kind: "internal" }, { kind: "glob", pattern: "langfuse-*" }],
        },
        {
          kind: "and",
          args: [
            { kind: "not", arg: { kind: "internal" } },
            { kind: "not", arg: { kind: "eq", value: "production" } },
          ],
        },
      ],
    });
  });

  it("escapes LIKE wildcards in literal parts of a glob", () => {
    expect(globToLikePattern("my_env-*")).toBe("my\\_env-%");
  });

  it("agrees with the resolver on random grants and environments", () => {
    // Park–Miller MINSTD; the product stays below 2^53, so arithmetic is exact.
    const MODULUS = 2147483647;
    let seed = 7919;
    const random = () => {
      seed = (seed * 48271) % MODULUS;
      return seed / MODULUS;
    };
    const pick = <T>(items: readonly T[]): T =>
      items[Math.floor(random() * items.length)];
    const word = (alphabet: string, maxLength: number) =>
      Array.from({ length: 1 + Math.floor(random() * maxLength) }, () =>
        pick([...alphabet]),
      ).join("");
    const roles: SystemRole[] = [
      "MEMBER",
      "VIEWER",
      "NONE",
      "INGEST",
      "SCORES_INGEST",
    ];
    const actions: ProjectAction[] = [
      "traces:read",
      "scores:save",
      "traces:create",
      "traces:delete",
    ];

    for (let run = 0; run < 500; run++) {
      const grants = new Map<string, EnvironmentGrant>();
      const grantCount = 1 + Math.floor(random() * 5);
      for (let i = 0; i < grantCount; i++) {
        const body = word("ab_-*", 4);
        const pattern = EnvironmentPatternSchema.parse(
          random() < 0.2 ? `langfuse-${body}` : body,
        );
        grants.set(pattern, { pattern, role: pick(roles) });
      }
      const access = compileEnvironmentAccess(
        pick(["MEMBER", "VIEWER", "INGEST"] as const),
        [...grants.values()],
      );
      for (const action of actions) {
        const predicate = toEnvironmentPredicate(
          toEnvironmentDecisionList(access, action),
        );
        for (let i = 0; i < 20; i++) {
          const body = word("abx_-", 5);
          const environment = random() < 0.2 ? `langfuse-${body}` : body;
          expect(
            evaluate(predicate, environment),
            JSON.stringify({ access, environment, action }),
          ).toBe(hasEnvironmentAccess(access, environment, action));
        }
      }
    }
  });
});
