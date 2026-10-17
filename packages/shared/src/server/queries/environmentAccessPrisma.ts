import { Prisma } from "@prisma/client";

import {
  INTERNAL_ENVIRONMENT_PREFIX,
  type EnvironmentDecisionList,
} from "../../features/rbac/environmentAccess";
import {
  toEnvironmentPredicate,
  type EnvironmentPredicate,
} from "../../features/rbac/environmentPredicate";
import { escapeSqlLikePattern, globToLikePattern } from "../utils/sqlLike";

/**
 * environmentAccessPrismaSql renders an environment decision list as a
 * Postgres boolean over `column`, for raw queries that read an environment
 * column (e.g. `trace_sessions.environment`).
 */
export function environmentAccessPrismaSql(
  decisions: EnvironmentDecisionList,
  column: Prisma.Sql,
): Prisma.Sql {
  const render = (node: EnvironmentPredicate): Prisma.Sql => {
    switch (node.kind) {
      case "const":
        return node.value ? Prisma.sql`TRUE` : Prisma.sql`FALSE`;
      case "eq":
        return Prisma.sql`${column} = ${node.value}`;
      case "glob":
        return Prisma.sql`${column} LIKE ${globToLikePattern(node.pattern)}`;
      case "internal":
        return Prisma.sql`${column} LIKE ${`${escapeSqlLikePattern(INTERNAL_ENVIRONMENT_PREFIX)}%`}`;
      case "not":
        return Prisma.sql`NOT (${render(node.arg)})`;
      case "and":
      case "or":
        return Prisma.sql`(${Prisma.join(
          node.args.map(render),
          node.kind === "and" ? " AND " : " OR ",
        )})`;
    }
  };
  return render(toEnvironmentPredicate(decisions));
}
