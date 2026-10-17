/**
 * Escapes SQL LIKE/ILIKE wildcard characters for literal matching.
 */
export const escapeSqlLikePattern = (value: string): string =>
  value.replace(/\\/g, "\\\\").replace(/%/g, "\\%").replace(/_/g, "\\_");

/**
 * Converts an environment glob, where `*` matches any run of characters, into
 * a LIKE pattern that matches exactly the same strings.
 */
export const globToLikePattern = (glob: string): string =>
  glob.split("*").map(escapeSqlLikePattern).join("%");
