import {
  type EnvironmentDecisionBranch,
  type EnvironmentDecisionList,
} from "./environmentAccess";

/**
 * A dialect-neutral boolean formula over an environment column, built only
 * from equality, glob matching, the internal-namespace test, NOT, AND and OR
 * so every SQL backend can render it without dialect-specific functions.
 */
export type EnvironmentPredicate =
  | { kind: "const"; value: boolean }
  | { kind: "eq"; value: string }
  | { kind: "glob"; pattern: string }
  | { kind: "internal" }
  | { kind: "not"; arg: EnvironmentPredicate }
  | { kind: "and" | "or"; args: EnvironmentPredicate[] };

const TRUE: EnvironmentPredicate = { kind: "const", value: true };
const FALSE: EnvironmentPredicate = { kind: "const", value: false };

const not = (arg: EnvironmentPredicate): EnvironmentPredicate => {
  if (arg.kind === "const") return arg.value ? FALSE : TRUE;
  if (arg.kind === "not") return arg.arg;
  return { kind: "not", arg };
};

/** junction flattens nested junctions of the same kind and folds constants. */
const junction = (
  kind: "and" | "or",
  args: EnvironmentPredicate[],
): EnvironmentPredicate => {
  const identity = kind === "and";
  const flat: EnvironmentPredicate[] = [];
  for (const arg of args) {
    if (arg.kind === "const") {
      if (arg.value === identity) continue;
      return arg;
    }
    flat.push(...(arg.kind === kind ? arg.args : [arg]));
  }
  if (flat.length === 0) return identity ? TRUE : FALSE;
  return flat.length === 1 ? flat[0] : { kind, args: flat };
};

/** A bare `*` matches every environment, so it folds to a constant. */
const match = (pattern: string): EnvironmentPredicate => {
  if (pattern === "*") return TRUE;
  return pattern.includes("*")
    ? { kind: "glob", pattern }
    : { kind: "eq", value: pattern };
};

/**
 * foldBranch turns first-match rules into a formula by folding from the right:
 * F(n+1) = fallback and F(i) = allow(i) ? m(i) ∨ F(i+1) : ¬m(i) ∧ F(i+1),
 * which equals "if m(i) then allow(i) else F(i+1)".
 */
const foldBranch = (branch: EnvironmentDecisionBranch): EnvironmentPredicate =>
  branch.rules.reduceRight<EnvironmentPredicate>(
    (rest, rule) =>
      rule.allow
        ? junction("or", [match(rule.pattern), rest])
        : junction("and", [not(match(rule.pattern)), rest]),
    branch.fallback ? TRUE : FALSE,
  );

/** toEnvironmentPredicate compiles a decision list into a simplified formula. */
export const toEnvironmentPredicate = (
  list: EnvironmentDecisionList,
): EnvironmentPredicate => {
  if (list.kind === "constant") return list.allow ? TRUE : FALSE;
  const internal: EnvironmentPredicate = { kind: "internal" };
  return junction("or", [
    junction("and", [internal, foldBranch(list.internal)]),
    junction("and", [not(internal), foldBranch(list.public)]),
  ]);
};
