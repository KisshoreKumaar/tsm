import type { RuleAction, RuleDetail, RuleSummary } from "./types";

export const ACTION_LABELS: Record<RuleAction, string> = {
  edit: "New version",
  backtest: "Backtest",
  approve: "Approve",
  activate: "Activate",
  disable: "Disable",
  retire: "Retire",
};

export const ACTION_PERMISSION: Record<RuleAction, string> = {
  edit: "rules.draft",
  backtest: "rules.draft",
  approve: "rules.approve",
  activate: "rules.approve",
  disable: "rules.approve",
  retire: "rules.approve",
};

/** Why the server would refuse this action, for a disabled button's tooltip. Null when it is allowed. */
export function blockedReason(rule: RuleSummary, action: RuleAction): string | null {
  if (rule.allowed_actions.includes(action)) return null;
  if (rule.status === "RETIRED") return "This rule is retired";
  switch (action) {
    case "approve":
      return rule.status === "DRAFT"
        ? `Backtest version ${rule.current_version} first`
        : `A ${rule.status} rule cannot be approved again`;
    case "activate":
      return rule.approved_version === rule.current_version
        ? `Version ${rule.current_version} is already active`
        : `Approve version ${rule.current_version} first`;
    case "disable":
      return rule.active_version === null ? "This rule has never been activated" : "This rule is already disabled";
    default:
      return `Not available while the rule is ${rule.status}`;
  }
}

export function runsNow(rule: RuleSummary): boolean {
  return rule.active_version !== null && rule.status !== "DISABLED" && rule.status !== "RETIRED";
}

/** Explains the common case where a newer draft exists while an older version keeps detecting. */
export function versionNote(rule: RuleSummary): string | null {
  if (rule.active_version === null) return "No version has been activated yet, so this rule does not detect anything.";
  if (rule.active_version !== rule.current_version) {
    return `Version ${rule.current_version} is ${rule.status.toLowerCase()}; version ${rule.active_version} keeps running until you activate the new one.`;
  }
  return runsNow(rule) ? `Version ${rule.active_version} is running.` : `Version ${rule.active_version} is not running.`;
}

export function latestBacktest(rule: RuleDetail): RuleDetail["backtests"][number] | null {
  return rule.backtests.find((backtest) => backtest.version === rule.current_version) ?? null;
}
