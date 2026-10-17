import { z } from "zod";
import { type SystemRole } from "../../db";
import {
  systemRoleAccessRights,
  type ProjectAction,
} from "./systemRoleAccessRights";

/**
 * Environment-level roles narrow a principal's project role per environment.
 *
 * A grant pairs an environment pattern (exact name or `*` glob) with a role.
 * For an environment `e`, the effective project actions are
 *
 *   A(base) ∩ ⋂ { A(g.role) : g ∈ M*(e) }   if some grant matches `e`
 *   A(base)                                  if none matches and `e` is public
 *   ∅                                        if none matches and `e` is internal
 *
 * where `A(r)` is the project action set of role `r` and `M*(e)` is the set of
 * matching grants of maximal specificity (an exact name outranks any glob;
 * among globs, more literal characters rank higher). Ties intersect, so the
 * result is independent of grant order, and it is always a subset of `A(base)`:
 * grants can lower a role but never raise it.
 *
 * Internal `langfuse*` environments are reachable only through patterns that
 * start with `langfuse-`; a bare `*` never matches them. Such patterns in turn
 * match only internal environments, so the two namespaces are disjoint.
 */

/** Prefix of the reserved internal environment namespace. */
export const INTERNAL_ENVIRONMENT_PREFIX = "langfuse";
const INTERNAL_PATTERN_PREFIX = "langfuse-";

/** Roles that hold project administration and therefore ignore environment grants. */
const UNRESTRICTABLE_ROLES: ReadonlySet<SystemRole> = new Set<SystemRole>([
  "OWNER",
  "ADMIN",
]);

/** isInternalEnvironment reports whether an environment belongs to the reserved Langfuse namespace. */
export const isInternalEnvironment = (environment: string): boolean =>
  environment.startsWith(INTERNAL_ENVIRONMENT_PREFIX);

/** isUnrestrictableRole reports whether a project role ignores environment grants. */
export const isUnrestrictableRole = (role: SystemRole): boolean =>
  UNRESTRICTABLE_ROLES.has(role);

/** normalizeEnvironmentPattern lowercases a pattern and collapses repeated wildcards. */
const normalizeEnvironmentPattern = (pattern: string): string =>
  pattern.trim().toLowerCase().replace(/\*+/g, "*");

/** EnvironmentPatternSchema validates and normalizes a grant pattern, e.g. `production` or `dev-*`. */
export const EnvironmentPatternSchema = z
  .string()
  .transform(normalizeEnvironmentPattern)
  .pipe(
    z
      .string()
      .min(1)
      .max(64)
      .regex(
        /^[a-z0-9_*-]+$/,
        "Use lowercase letters, digits, '-', '_' and '*' only",
      )
      .refine(
        (pattern) =>
          !pattern.startsWith(INTERNAL_ENVIRONMENT_PREFIX) ||
          pattern.startsWith(INTERNAL_PATTERN_PREFIX),
        "Internal environment patterns must start with 'langfuse-'",
      ),
  );

/** EnvironmentGrant assigns a role to every environment matching a pattern. */
export type EnvironmentGrant = { pattern: string; role: SystemRole };

/** RestrictedEnvironmentAccess holds a principal's grants, sorted most specific first. */
export type RestrictedEnvironmentAccess = {
  kind: "restricted";
  baseRole: SystemRole;
  grants: readonly EnvironmentGrant[];
};

/** EnvironmentAccess is a principal's compiled environment restriction within one project. */
export type EnvironmentAccess =
  | { kind: "unrestricted" }
  | RestrictedEnvironmentAccess;

type Specificity = { exact: boolean; literals: number };

const specificity = (pattern: string): Specificity => ({
  exact: !pattern.includes("*"),
  literals: pattern.replace(/\*/g, "").length,
});

/** compareSpecificity orders patterns most specific first; zero means a tie. */
const compareSpecificity = (a: string, b: string): number => {
  const sa = specificity(a);
  const sb = specificity(b);
  if (sa.exact !== sb.exact) return sa.exact ? -1 : 1;
  return sb.literals - sa.literals;
};

/** compileEnvironmentAccess builds a principal's access from its project role and grants. */
export const compileEnvironmentAccess = (
  baseRole: SystemRole,
  grants: readonly EnvironmentGrant[],
): EnvironmentAccess => {
  if (grants.length === 0 || isUnrestrictableRole(baseRole)) {
    return { kind: "unrestricted" };
  }
  const sorted = grants
    .map((grant) => ({
      pattern: normalizeEnvironmentPattern(grant.pattern),
      role: grant.role,
    }))
    .sort(
      (a, b) =>
        compareSpecificity(a.pattern, b.pattern) ||
        a.pattern.localeCompare(b.pattern),
    );
  return { kind: "restricted", baseRole, grants: sorted };
};

const globToRegExp = (pattern: string): RegExp =>
  new RegExp(
    `^${pattern
      .split("*")
      .map((part) => part.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"))
      .join(".*")}$`,
  );

/** matchesEnvironmentPattern reports whether a normalized pattern covers an environment. */
export const matchesEnvironmentPattern = (
  pattern: string,
  environment: string,
): boolean => {
  if (
    isInternalEnvironment(environment) !==
    pattern.startsWith(INTERNAL_PATTERN_PREFIX)
  ) {
    return false;
  }
  return globToRegExp(pattern).test(environment);
};

/** User roles from least to most privileged. */
const USER_ROLE_ORDER: readonly SystemRole[] = [
  "NONE",
  "VIEWER",
  "MEMBER",
  "ADMIN",
  "OWNER",
];

const ownProjectActions = (role: SystemRole): Set<ProjectAction> => {
  const allowed = new Set<ProjectAction>();
  const denied = new Set<ProjectAction>();
  for (const policy of systemRoleAccessRights[role].policies) {
    if (policy.resourceKind !== "project") continue;
    for (const action of policy.actions) {
      (policy.effect === "ALLOW" ? allowed : denied).add(action);
    }
  }
  for (const action of denied) allowed.delete(action);
  return allowed;
};

const projectActionsCache = new Map<SystemRole, ReadonlySet<ProjectAction>>();

/**
 * projectActionsForRole is the set of project actions a role allows, net of
 * denies. The per-role scope tables are not nested (VIEWER lists read scopes
 * that MEMBER omits because user reads are not scope-checked), so a user role
 * also holds every action of the user roles ranked below it. This makes user
 * roles a chain under inclusion, and intersecting two of them yields the lower
 * one. Api-key roles are unordered and keep their own actions.
 */
export const projectActionsForRole = (
  role: SystemRole,
): ReadonlySet<ProjectAction> => {
  const cached = projectActionsCache.get(role);
  if (cached) return cached;
  const rank = USER_ROLE_ORDER.indexOf(role);
  const actions =
    rank === -1
      ? ownProjectActions(role)
      : new Set(
          USER_ROLE_ORDER.slice(0, rank + 1).flatMap((lower) => [
            ...ownProjectActions(lower),
          ]),
        );
  projectActionsCache.set(role, actions);
  return actions;
};

/** mostSpecificMatches returns the matching grants of maximal specificity. */
const mostSpecificMatches = (
  grants: readonly EnvironmentGrant[],
  environment: string,
): EnvironmentGrant[] => {
  const matches = grants.filter((grant) =>
    matchesEnvironmentPattern(grant.pattern, environment),
  );
  if (matches.length === 0) return [];
  return matches.filter(
    (grant) => compareSpecificity(grant.pattern, matches[0].pattern) === 0,
  );
};

/** resolveEnvironmentActions computes the project actions a restricted principal holds in one environment. */
export const resolveEnvironmentActions = (
  access: RestrictedEnvironmentAccess,
  environment: string,
): ReadonlySet<ProjectAction> => {
  const matches = mostSpecificMatches(access.grants, environment);
  if (matches.length === 0) {
    return isInternalEnvironment(environment)
      ? new Set()
      : projectActionsForRole(access.baseRole);
  }
  const effective = new Set(projectActionsForRole(access.baseRole));
  for (const grant of matches) {
    const granted = projectActionsForRole(grant.role);
    for (const action of effective) {
      if (!granted.has(action)) effective.delete(action);
    }
  }
  return effective;
};

/**
 * hasEnvironmentAccess reports whether the environment restriction permits an
 * action. It does not replace the project-role check: an unrestricted
 * principal is still bounded by its project role.
 */
export const hasEnvironmentAccess = (
  access: EnvironmentAccess,
  environment: string,
  action: ProjectAction,
): boolean =>
  access.kind === "unrestricted" ||
  resolveEnvironmentActions(access, environment).has(action);

/** EnvironmentDecisionRule allows or denies every environment its glob covers. */
export type EnvironmentDecisionRule = { pattern: string; allow: boolean };

/** EnvironmentDecisionBranch is evaluated first-match over plain glob matching, falling back when no rule matches. */
export type EnvironmentDecisionBranch = {
  rules: EnvironmentDecisionRule[];
  fallback: boolean;
};

/**
 * EnvironmentDecisionList answers one action for every environment, split by
 * namespace so each branch uses plain glob semantics (SQL `LIKE`): `internal`
 * applies to environments starting with `langfuse`, `public` to the rest.
 */
export type EnvironmentDecisionList =
  | { kind: "constant"; allow: boolean }
  | {
      kind: "rules";
      internal: EnvironmentDecisionBranch;
      public: EnvironmentDecisionBranch;
    };

const buildBranch = (
  grants: readonly EnvironmentGrant[],
  verdict: (grant: EnvironmentGrant) => boolean,
  fallback: boolean,
): EnvironmentDecisionBranch => {
  // Grants arrive most specific first. Within a tie group, denies come first,
  // so first-match evaluation equals the intersection over the group.
  const rules: EnvironmentDecisionRule[] = [];
  let groupStart = 0;
  while (groupStart < grants.length) {
    let groupEnd = groupStart + 1;
    while (
      groupEnd < grants.length &&
      compareSpecificity(
        grants[groupStart].pattern,
        grants[groupEnd].pattern,
      ) === 0
    ) {
      groupEnd++;
    }
    const group = grants
      .slice(groupStart, groupEnd)
      .map((grant) => ({ pattern: grant.pattern, allow: verdict(grant) }));
    rules.push(
      ...group.filter((rule) => !rule.allow),
      ...group.filter((rule) => rule.allow),
    );
    groupStart = groupEnd;
  }
  // Trailing rules that agree with the fallback cannot change any outcome.
  while (rules.length > 0 && rules[rules.length - 1].allow === fallback) {
    rules.pop();
  }
  return { rules, fallback };
};

/** toEnvironmentDecisionList compiles access for one action into ordered glob rules for query filters. */
export const toEnvironmentDecisionList = (
  access: EnvironmentAccess,
  action: ProjectAction,
): EnvironmentDecisionList => {
  if (access.kind === "unrestricted") return { kind: "constant", allow: true };
  if (!projectActionsForRole(access.baseRole).has(action)) {
    return { kind: "constant", allow: false };
  }
  const verdict = (grant: EnvironmentGrant) =>
    projectActionsForRole(grant.role).has(action);
  const internal = buildBranch(
    access.grants.filter((grant) =>
      grant.pattern.startsWith(INTERNAL_PATTERN_PREFIX),
    ),
    verdict,
    false,
  );
  const publicBranch = buildBranch(
    access.grants.filter(
      (grant) => !grant.pattern.startsWith(INTERNAL_PATTERN_PREFIX),
    ),
    verdict,
    true,
  );
  return { kind: "rules", internal, public: publicBranch };
};
