import type { AbstractCondition, AbstractPolicy, AbstractStatement } from "../api/types";

/**
 * CREATE_ROLE 的权限声明（policy_text）解析。
 *
 * 文本框同时接受两种写法：
 *  - 平台抽象策略：{"name": "...", "statements": [{"effect": "Allow", ...}]}
 *  - AWS IAM 策略文档：{"Version": "...", "Statement": [{"Effect": ..., ...}]}
 *
 * AWS 写法是运维手里最常见的格式（复制粘贴现网文档即可），这里就地转换成抽象
 * 模型再提交：动作/资源/条件一一对应，之后仍走平台的抽象链路（动作映射、风险
 * 评审、Terraform 生成），行为不变。Sid 不在抽象模型里，会被丢弃。
 */

export class AbstractPolicyParseError extends Error {
  readonly detail: string;

  constructor(detail: string) {
    super(detail);
    this.name = "AbstractPolicyParseError";
    this.detail = detail;
  }
}

type RecordLike = Record<string, unknown>;

const EFFECTS = ["Allow", "Deny"];

function asStringList(value: unknown): string[] | undefined {
  const list = Array.isArray(value) ? value : value === undefined || value === null ? [] : [value];
  const strings = list
    .map((item) => (typeof item === "string" ? item.trim() : ""))
    .filter((item) => item.length > 0);
  return strings.length > 0 ? strings : undefined;
}

function conditionValues(value: unknown): unknown[] {
  return Array.isArray(value) ? value : [value];
}

/**
 * AWS Condition → 抽象 conditions：
 * {"StringEquals": {"aws:PrincipalTag/team": "a"}} →
 * [{key: "aws:PrincipalTag/team", operator: "StringEquals", values: ["a"]}]
 */
function convertConditions(raw: unknown): AbstractCondition[] | undefined {
  if (raw === undefined || raw === null) return undefined;
  // 抽象写法（数组）直接沿用。
  if (Array.isArray(raw)) return raw as AbstractCondition[];
  if (typeof raw !== "object") return undefined;
  const conditions: AbstractCondition[] = [];
  for (const [operator, entries] of Object.entries(raw as RecordLike)) {
    if (!entries || typeof entries !== "object" || Array.isArray(entries)) continue;
    for (const [key, value] of Object.entries(entries as RecordLike)) {
      conditions.push({ key, operator, values: conditionValues(value) });
    }
  }
  return conditions.length > 0 ? conditions : undefined;
}

function convertAwsStatement(raw: unknown, index: number): AbstractStatement {
  if (!raw || typeof raw !== "object" || Array.isArray(raw)) {
    throw new AbstractPolicyParseError(`statement[${index}] must be an object`);
  }
  const source = raw as RecordLike;
  const effect = typeof source.Effect === "string" ? source.Effect : undefined;
  if (!effect || !EFFECTS.includes(effect)) {
    throw new AbstractPolicyParseError(`statement[${index}].Effect must be Allow or Deny`);
  }
  const actions = asStringList(source.Action) ?? asStringList(source.actions);
  const notActions = asStringList(source.NotAction) ?? asStringList(source.not_actions);
  const resources = asStringList(source.Resource) ?? asStringList(source.resources);
  const notResources = asStringList(source.NotResource) ?? asStringList(source.not_resources);
  if (!actions && !notActions) {
    throw new AbstractPolicyParseError(`statement[${index}] must specify Action`);
  }
  if (!resources && !notResources) {
    throw new AbstractPolicyParseError(`statement[${index}] must specify Resource`);
  }
  const conditions = convertConditions(source.Condition ?? source.conditions);
  const statement: AbstractStatement = { effect };
  if (actions) statement.actions = actions;
  if (notActions) statement.not_actions = notActions;
  if (resources) statement.resources = resources;
  if (notResources) statement.not_resources = notResources;
  if (conditions) statement.conditions = conditions;
  return statement;
}

/**
 * 解析 policy_text 并返回可提交的 abstract_policy。
 *
 * name 由调用方传入：后端要求 abstract_policy.name == principal_name == role.name，
 * 所以这里强制对齐，用户写错也不会 400。
 *
 * @throws {AbstractPolicyParseError} 文本不是合法 JSON，或两种写法都对不上时。
 */
export function parseAbstractPolicyText(text: string, name: string): AbstractPolicy {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch (error) {
    throw new AbstractPolicyParseError(error instanceof Error ? error.message : "invalid JSON");
  }
  if (!parsed || typeof parsed !== "object" || Array.isArray(parsed)) {
    throw new AbstractPolicyParseError("policy must be a JSON object");
  }
  const source = parsed as RecordLike;
  // AWS 文档用 "Statement"，抽象写法用 "statements"：有前者就按 AWS 文档转换。
  if (Array.isArray(source.Statement)) {
    const statements = (source.Statement as unknown[]).map(convertAwsStatement);
    if (statements.length === 0) {
      throw new AbstractPolicyParseError("Statement must contain at least one statement");
    }
    return { name, statements };
  }
  const statements = Array.isArray(source.statements) ? (source.statements as AbstractStatement[]) : [];
  return {
    ...(source as Partial<AbstractPolicy>),
    name,
    statements,
  };
}

/** 抽象策略示例：作为文本框 placeholder，让用户一眼看到该写什么。 */
export const ABSTRACT_POLICY_TEMPLATE = `{
  "statements": [
    {
      "effect": "Allow",
      "actions": ["sns:Publish"],
      "resources": ["arn:aws:sns:ap-southeast-1:123456789012:my-topic"]
    }
  ]
}`;
