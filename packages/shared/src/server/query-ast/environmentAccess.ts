/**
 * Environment access filtering. Opt-in per compile: runs only when the caller
 * passes an environment decision list to `compileClickhouseQuery`.
 *
 * Every FROM/JOIN relation whose registry entry has an `environment` column
 * gets the access predicate: AND-ed into the ON clause for a JOIN with one,
 * prepended to the WHERE otherwise. A RIGHT or FULL JOIN in such a select
 * fails to compile, since neither placement can drop the preserved side's
 * rows. Nested selects are filtered on their own, and CTE names are skipped
 * because the CTE body is filtered where it reads the table.
 */
import {
  AliasNode,
  AndNode,
  BinaryOperationNode,
  ColumnNode,
  IdentifierNode,
  JoinNode,
  OperatorNode,
  OrNode,
  ParensNode,
  ReferenceNode,
  TableNode,
  UnaryOperationNode,
  ValueNode,
  WhereNode,
  type CommonTableExpressionNode,
  type JoinType,
  type KyselyPlugin,
  type OperationNode,
  type PluginTransformQueryArgs,
  type PluginTransformResultArgs,
  type QueryId,
  type RootOperationNode,
  type SelectQueryNode,
  type WithNode,
} from "kysely";

import {
  INTERNAL_ENVIRONMENT_PREFIX,
  type EnvironmentDecisionList,
} from "../../features/rbac/environmentAccess";
import {
  toEnvironmentPredicate,
  type EnvironmentPredicate,
} from "../../features/rbac/environmentPredicate";
import { escapeSqlLikePattern, globToLikePattern } from "../utils/sqlLike";
import { QueryCompileError } from "./errors";
import {
  FinalTableNode,
  unwrapFinalTable,
  type ClickHouseSelectQueryNode,
} from "./nodes";
import { TABLE_COLUMN_TYPES } from "./schema";
import { ClickHouseOperationNodeTransformer } from "./transformer";

const ENVIRONMENT_COLUMN = "environment";

/** Registry tables that carry an environment column. */
export const ENVIRONMENT_TABLES = new Set<string>(
  Object.entries(TABLE_COLUMN_TYPES)
    .filter(([, columns]) => ENVIRONMENT_COLUMN in columns)
    .map(([table]) => table),
);

const OUTER_PRESERVING_JOINS = new Set<JoinType>(["RightJoin", "FullJoin"]);

export class EnvironmentAccessPlugin implements KyselyPlugin {
  private readonly predicate: EnvironmentPredicate;

  constructor(decisions: EnvironmentDecisionList) {
    this.predicate = toEnvironmentPredicate(decisions);
  }

  transformQuery(args: PluginTransformQueryArgs): RootOperationNode {
    return new EnvironmentAccessTransformer(this.predicate).transformNode(
      args.node,
    ) as RootOperationNode;
  }

  async transformResult(args: PluginTransformResultArgs) {
    return args.result;
  }
}

class EnvironmentAccessTransformer extends ClickHouseOperationNodeTransformer {
  /** CTE names visible to the select being transformed; see softDelete.ts. */
  private readonly cteScopes: Set<string>[] = [];

  constructor(private readonly predicate: EnvironmentPredicate) {
    super();
  }

  protected override transformSelectQuery(
    node: SelectQueryNode,
    queryId?: QueryId,
  ): SelectQueryNode {
    const ctes = cteNames(node.with);
    if (ctes.size > 0) this.cteScopes.push(ctes);
    try {
      const withChildren = super.transformSelectQuery(
        node,
        queryId,
      ) as ClickHouseSelectQueryNode;
      return this.filterSelect(withChildren);
    } finally {
      if (ctes.size > 0) this.cteScopes.pop();
    }
  }

  protected override transformWith(
    node: WithNode,
    queryId?: QueryId,
  ): WithNode {
    const full = this.cteScopes.pop() ?? new Set<string>();
    try {
      const expressions = node.expressions.map((expr) => {
        const visible = new Set(full);
        visible.delete(cteName(expr));
        this.cteScopes.push(visible);
        try {
          return this.transformNode(expr, queryId);
        } finally {
          this.cteScopes.pop();
        }
      });
      return { ...node, expressions };
    } finally {
      if (full.size > 0) this.cteScopes.push(full);
    }
  }

  private filterSelect(
    node: ClickHouseSelectQueryNode,
  ): ClickHouseSelectQueryNode {
    const describe = (item: OperationNode) => {
      const relation = describeRelation(item);
      return relation &&
        !this.cteScopes.some((scope) => scope.has(relation.tableName))
        ? relation
        : undefined;
    };
    const froms = (node.from?.froms ?? []).map(describe);
    const joins = (node.joins ?? []).map((join) => ({
      join,
      relation: describe(join.table),
    }));

    const readsEnvironment =
      froms.some(Boolean) || joins.some(({ relation }) => relation);
    if (!readsEnvironment) return node;

    const outerJoin = joins.find(({ join }) =>
      OUTER_PRESERVING_JOINS.has(join.joinType),
    );
    if (outerJoin) {
      throw new QueryCompileError(
        `${outerJoin.join.joinType} is not supported on an environment-restricted select. Filter the table in a subquery instead.`,
      );
    }

    const whereRelations = [
      ...froms,
      ...joins.filter(({ join }) => !join.on).map(({ relation }) => relation),
    ];
    let where = node.where;
    for (const relation of whereRelations) {
      if (!relation) continue;
      const predicate = renderPredicate(this.predicate, relation);
      where = where
        ? WhereNode.create(AndNode.create(predicate, where.where))
        : WhereNode.create(predicate);
    }

    const filteredJoins = joins.map(({ join, relation }) =>
      relation && join.on
        ? JoinNode.cloneWithOn(join, renderPredicate(this.predicate, relation))
        : join,
    );

    return {
      ...node,
      ...(where ? { where } : {}),
      ...(filteredJoins.length > 0 ? { joins: filteredJoins } : {}),
    };
  }
}

type EnvironmentRelation = { tableName: string; alias?: string };

function cteName(expr: CommonTableExpressionNode): string {
  return expr.name.table.table.identifier.name;
}

function cteNames(node: WithNode | undefined): Set<string> {
  return new Set((node?.expressions ?? []).map(cteName));
}

function describeRelation(
  node: OperationNode,
): EnvironmentRelation | undefined {
  if (FinalTableNode.is(node)) {
    return describeRelation(unwrapFinalTable(node));
  }
  if (AliasNode.is(node)) {
    const inner = describeRelation(node.node);
    if (!inner || !IdentifierNode.is(node.alias)) return inner;
    return { ...inner, alias: node.alias.name };
  }
  if (TableNode.is(node)) {
    const tableName = node.table.identifier.name;
    return ENVIRONMENT_TABLES.has(tableName) ? { tableName } : undefined;
  }
  return undefined;
}

/** Always qualified, so a same-named SELECT alias cannot capture the column. */
function renderPredicate(
  predicate: EnvironmentPredicate,
  relation: EnvironmentRelation,
): OperationNode {
  const column = ReferenceNode.create(
    ColumnNode.create(ENVIRONMENT_COLUMN),
    TableNode.create(relation.alias ?? relation.tableName),
  );
  const compare = (operator: "=" | "like", value: string) =>
    BinaryOperationNode.create(
      column,
      OperatorNode.create(operator),
      ValueNode.create(value),
    );
  const render = (node: EnvironmentPredicate): OperationNode => {
    switch (node.kind) {
      case "const":
        return BinaryOperationNode.create(
          ValueNode.createImmediate(1),
          OperatorNode.create("="),
          ValueNode.createImmediate(node.value ? 1 : 0),
        );
      case "eq":
        return compare("=", node.value);
      case "glob":
        return compare("like", globToLikePattern(node.pattern));
      case "internal":
        return compare(
          "like",
          `${escapeSqlLikePattern(INTERNAL_ENVIRONMENT_PREFIX)}%`,
        );
      case "not":
        return UnaryOperationNode.create(
          OperatorNode.create("not"),
          ParensNode.create(render(node.arg)),
        );
      case "and":
      case "or": {
        const combine = node.kind === "and" ? AndNode.create : OrNode.create;
        return ParensNode.create(
          node.args.map(render).reduce((left, right) => combine(left, right)),
        );
      }
    }
  };
  return render(predicate);
}
