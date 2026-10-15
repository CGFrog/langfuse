import { describe, expect, it } from "vitest";
import { type SystemRole } from "../../db";
import {
  compileEnvironmentAccess,
  EnvironmentPatternSchema,
  hasEnvironmentAccess,
  matchesEnvironmentPattern,
  projectActionsForRole,
  resolveEnvironmentActions,
  toEnvironmentDecisionList,
  type EnvironmentAccess,
  type EnvironmentDecisionList,
  type EnvironmentGrant,
  type RestrictedEnvironmentAccess,
} from "./environmentAccess";
import { type ProjectAction } from "./systemRoleAccessRights";

const restricted = (
  baseRole: SystemRole,
  grants: EnvironmentGrant[],
): RestrictedEnvironmentAccess => {
  const access = compileEnvironmentAccess(baseRole, grants);
  if (access.kind !== "restricted") throw new Error("expected restricted");
  return access;
};

/** Glob matching by dynamic programming, independent of the resolver's regex. */
const likeMatch = (pattern: string, value: string): boolean => {
  const m = pattern.length;
  const n = value.length;
  let prev = Array<boolean>(n + 1).fill(false);
  prev[0] = true;
  for (let i = 1; i <= m; i++) {
    const cur = Array<boolean>(n + 1).fill(false);
    const p = pattern[i - 1];
    cur[0] = p === "*" && prev[0];
    for (let j = 1; j <= n; j++) {
      cur[j] =
        p === "*" ? prev[j] || cur[j - 1] : prev[j - 1] && p === value[j - 1];
    }
    prev = cur;
  }
  return prev[n];
};

/** Evaluates a decision list the way a SQL `multiIf` over `LIKE` would. */
const evaluateDecisionList = (
  list: EnvironmentDecisionList,
  environment: string,
): boolean => {
  if (list.kind === "constant") return list.allow;
  const branch = environment.startsWith("langfuse")
    ? list.internal
    : list.public;
  const rule = branch.rules.find((r) => likeMatch(r.pattern, environment));
  return rule ? rule.allow : branch.fallback;
};

describe("EnvironmentPatternSchema", () => {
  it("normalizes case, whitespace and repeated wildcards", () => {
    expect(EnvironmentPatternSchema.parse("  Dev-**  ")).toBe("dev-*");
  });

  it.each(["", "prod env", "prod.env", "PROD%", "langfuse*", "langfuse_x"])(
    "rejects %j",
    (pattern) => {
      expect(EnvironmentPatternSchema.safeParse(pattern).success).toBe(false);
    },
  );

  it.each(["*", "production", "dev-*", "*-eu", "langfuse-*", "my_env"])(
    "accepts %j",
    (pattern) => {
      expect(EnvironmentPatternSchema.safeParse(pattern).success).toBe(true);
    },
  );
});

describe("matchesEnvironmentPattern", () => {
  it("treats '_' and '-' as literals", () => {
    expect(matchesEnvironmentPattern("my_env", "my_env")).toBe(true);
    expect(matchesEnvironmentPattern("my_env", "myxenv")).toBe(false);
  });

  it("keeps internal and public namespaces disjoint", () => {
    expect(matchesEnvironmentPattern("*", "langfuse-llm-as-a-judge")).toBe(
      false,
    );
    expect(
      matchesEnvironmentPattern("langfuse-*", "langfuse-llm-as-a-judge"),
    ).toBe(true);
    expect(matchesEnvironmentPattern("langfuse-*", "production")).toBe(false);
  });
});

describe("projectActionsForRole", () => {
  it("orders user roles as a chain under inclusion", () => {
    const chain: SystemRole[] = ["NONE", "VIEWER", "MEMBER", "ADMIN", "OWNER"];
    for (let i = 1; i < chain.length; i++) {
      const lower = projectActionsForRole(chain[i - 1]);
      const higher = projectActionsForRole(chain[i]);
      expect([...lower].filter((action) => !higher.has(action))).toEqual([]);
    }
  });
});

describe("compileEnvironmentAccess", () => {
  it("is unrestricted without grants", () => {
    expect(compileEnvironmentAccess("MEMBER", [])).toEqual({
      kind: "unrestricted",
    });
  });

  it.each<SystemRole>(["OWNER", "ADMIN"])("ignores grants for %s", (role) => {
    expect(
      compileEnvironmentAccess(role, [{ pattern: "*", role: "NONE" }]),
    ).toEqual({ kind: "unrestricted" });
  });

  it("does not depend on grant order", () => {
    const grants: EnvironmentGrant[] = [
      { pattern: "*", role: "NONE" },
      { pattern: "dev-*", role: "VIEWER" },
      { pattern: "staging", role: "MEMBER" },
    ];
    expect(compileEnvironmentAccess("MEMBER", grants)).toEqual(
      compileEnvironmentAccess("MEMBER", [...grants].reverse()),
    );
  });
});

describe("resolveEnvironmentActions", () => {
  // VIEWER in production, MEMBER in staging (inherited), NONE in secret-*.
  const access = restricted("MEMBER", [
    { pattern: "production", role: "VIEWER" },
    { pattern: "secret-*", role: "NONE" },
  ]);

  it("narrows matched environments to the grant", () => {
    expect(hasEnvironmentAccess(access, "production", "traces:read")).toBe(
      true,
    );
    expect(hasEnvironmentAccess(access, "production", "scores:save")).toBe(
      false,
    );
    expect(hasEnvironmentAccess(access, "secret-x", "traces:read")).toBe(false);
  });

  it("falls back to the project role for unmatched public environments", () => {
    expect(resolveEnvironmentActions(access, "staging")).toEqual(
      projectActionsForRole("MEMBER"),
    );
  });

  it("denies unmatched internal environments", () => {
    expect(
      resolveEnvironmentActions(access, "langfuse-llm-as-a-judge").size,
    ).toBe(0);
  });

  it("prefers an exact name over any glob", () => {
    const a = restricted("MEMBER", [
      { pattern: "dev-*", role: "NONE" },
      { pattern: "dev-shared", role: "VIEWER" },
    ]);
    expect(hasEnvironmentAccess(a, "dev-shared", "traces:read")).toBe(true);
    expect(hasEnvironmentAccess(a, "dev-a", "traces:read")).toBe(false);
  });

  it("prefers the glob with more literal characters", () => {
    const a = restricted("MEMBER", [
      { pattern: "*", role: "NONE" },
      { pattern: "dev-*", role: "VIEWER" },
    ]);
    expect(hasEnvironmentAccess(a, "dev-a", "traces:read")).toBe(true);
    expect(hasEnvironmentAccess(a, "production", "traces:read")).toBe(false);
  });

  it("intersects equally specific matches", () => {
    const a = restricted("MEMBER", [
      { pattern: "dev-*", role: "MEMBER" },
      { pattern: "*-dev", role: "VIEWER" },
    ]);
    expect(resolveEnvironmentActions(a, "dev-dev")).toEqual(
      projectActionsForRole("VIEWER"),
    );
  });

  it("never exceeds the project role", () => {
    const a = restricted("VIEWER", [{ pattern: "staging", role: "MEMBER" }]);
    expect(resolveEnvironmentActions(a, "staging")).toEqual(
      projectActionsForRole("VIEWER"),
    );
  });

  it("intersects non-linear api-key roles", () => {
    const a = restricted("INGEST", [{ pattern: "production", role: "VIEWER" }]);
    expect(resolveEnvironmentActions(a, "production").size).toBe(0);
    expect(hasEnvironmentAccess(a, "staging", "traces:create")).toBe(true);
  });
});

describe("toEnvironmentDecisionList", () => {
  it("is constant for unrestricted access and for actions above the project role", () => {
    expect(
      toEnvironmentDecisionList({ kind: "unrestricted" }, "traces:read"),
    ).toEqual({ kind: "constant", allow: true });
    expect(
      toEnvironmentDecisionList(
        restricted("VIEWER", [{ pattern: "*", role: "VIEWER" }]),
        "traces:delete",
      ),
    ).toEqual({ kind: "constant", allow: false });
  });

  it("drops trailing rules that agree with the fallback", () => {
    const list = toEnvironmentDecisionList(
      restricted("MEMBER", [
        { pattern: "production", role: "NONE" },
        { pattern: "dev-*", role: "VIEWER" },
      ]),
      "traces:read",
    );
    expect(list).toEqual({
      kind: "rules",
      internal: { rules: [], fallback: false },
      public: {
        rules: [{ pattern: "production", allow: false }],
        fallback: true,
      },
    });
  });

  it("agrees with the resolver on random grants and environments", () => {
    // Park–Miller MINSTD: a seeded PRNG so failures reproduce. The product
    // stays below 2^53, so floating-point arithmetic is exact.
    const MODULUS = 2147483647;
    let seed = 24301;
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
      const access: EnvironmentAccess = compileEnvironmentAccess(
        pick(["MEMBER", "VIEWER", "INGEST"] as const),
        [...grants.values()],
      );

      for (let i = 0; i < 20; i++) {
        const body = word("ab_-", 5);
        const environment = random() < 0.2 ? `langfuse-${body}` : body;
        for (const action of actions) {
          expect(
            evaluateDecisionList(
              toEnvironmentDecisionList(access, action),
              environment,
            ),
            JSON.stringify({ access, environment, action }),
          ).toBe(hasEnvironmentAccess(access, environment, action));
        }
      }
    }
  });
});
