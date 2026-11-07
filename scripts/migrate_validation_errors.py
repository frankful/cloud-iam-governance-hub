# -*- coding: utf-8 -*-
"""Migrate whitelisted-prefix error sites in ticket_service.go to apperr errors.

For every errors.New(...) / fmt.Errorf(...) call whose message literal starts
with one of the legacy isValidationError prefixes, replace the constructor:
  errors.New(x)   -> apperr.Validation(...)   (single string arg)
  fmt.Errorf(...) -> apperr.Validationf(...)
Non-literal or non-matching sites are left untouched. Behavior is unchanged:
all converted sites were already classified as 400 by the prefix whitelist.
"""
import re
import sys

PATH = "internal/service/ticket_service.go"

PREFIXES = [
    "submitter ", "unsupported ticket type", "account_id ", "principal_name ",
    "role.name ", "role.trust_policy", "role.policy_arns: ",
    "create_user.policy_arns: ", "create_group.policy_arns: ",
    "abstract_policy.", "abstract_policy ", "request_policy.principal.",
    "approval_mode ", "at least one approver_id ", "approver_ids ",
    "approver_id ", "no active approvers",
    "该资源已有创建工单在处理中", "该角色已有内嵌策略批量纳管工单在处理中",
    "该角色已有变更工单在处理中", "该策略已有变更工单在处理中",
    "该组已有成员变更工单在处理中", "该策略已挂载关系不存在于清单",
    "submitter cannot", "validate requested IAM policy:", "approver ",
    "approval result ", "approval reason ", "ticket number ",
    "either request_policy or abstract_policy", "update_role config",
    "update_role is identical", "update_role.inline_policies is no longer supported",
    "update_role.managed_policy_arns is no longer supported", "role ",
    "principal_type ", "managed_policy_arn: ", "load existing ", 'user "',
    "IAM user ", "IAM group ", 'group "', "validate role update terraform:",
    "validate policy update terraform:", "update_policy ", "update_policy.",
    "update_membership", "operation ", "AWS-managed policies cannot",
    "inline policy ", 'policy "', "policy arn:", "locate source attach ticket",
    "fetch role Terraform file", "fetch source Terraform file",
    "load managed policy", "load group inline policy",
    "check active update-policy tickets", "rollback target ",
    "update_policy config missing",
]

CALL_RE = re.compile(r"(errors\.New|fmt\.Errorf)\s*\(")


def skip_ws_comments(s, i):
    while i < len(s):
        c = s[i]
        if c in " \t\r\n":
            i += 1
        elif c == "/" and i + 1 < len(s) and s[i + 1] == "/":
            j = s.find("\n", i)
            i = len(s) if j == -1 else j + 1
        elif c == "/" and i + 1 < len(s) and s[i + 1] == "*":
            k = s.find("*/", i + 2)
            i = len(s) if k == -1 else k + 2
        else:
            break
    return i


def read_string_literal(s, i):
    """Read one Go string literal at i. Returns (value, next_index) or None."""
    if i >= len(s):
        return None
    if s[i] == '"':
        j = i + 1
        buf = []
        while j < len(s):
            c = s[j]
            if c == "\\":
                nxt = s[j + 1]
                mapping = {"n": "\n", "t": "\t", "r": "\r", '"': '"', "\\": "\\", "'": "'"}
                if nxt in mapping:
                    buf.append(mapping[nxt]); j += 2; continue
                if nxt == "u":
                    buf.append(chr(int(s[j + 2:j + 6], 16))); j += 6; continue
                return None  # unknown escape: bail out
            if c == '"':
                return "".join(buf), j + 1
            buf.append(c); j += 1
        return None
    if s[i] == "`":
        j = s.find("`", i + 1)
        if j == -1:
            return None
        return s[i + 1:j], j + 1
    return None


def parse_first_arg_value(s, open_idx, close_idx):
    """Parse the first argument of a call; return its string value if it is
    built solely from string literals (concatenation allowed), else None."""
    i = skip_ws_comments(s, open_idx + 1)
    parts = []
    depth = 0
    while True:
        i = skip_ws_comments(s, i)
        if i >= close_idx:
            return None
        lit = read_string_literal(s, i)
        if lit is None:
            return None
        val, i = lit
        parts.append(val)
        i = skip_ws_comments(s, i)
        if i < close_idx and s[i] == "+":
            i += 1
            continue
        break
    # must be at (optional) comma = end of first arg
    if i < close_idx and s[i] != ",":
        return None
    return "".join(parts)


def find_close_paren(s, open_idx):
    depth = 0
    i = open_idx
    while i < len(s):
        c = s[i]
        if c == '"':
            lit = read_string_literal(s, i)
            if lit is None:
                return -1
            i = lit[1] - 1
        elif c == "`":
            j = s.find("`", i + 1)
            if j == -1:
                return -1
            i = j
        elif c == "/" and i + 1 < len(s) and s[i + 1] == "/":
            j = s.find("\n", i)
            i = len(s) - 1 if j == -1 else j - 1
        elif c == "/" and i + 1 < len(s) and s[i + 1] == "*":
            k = s.find("*/", i + 2)
            if k == -1:
                return -1
            i = k + 1
        elif c == "(":
            depth += 1
        elif c == ")":
            depth -= 1
            if depth == 0:
                return i
        i += 1
    return -1


def main():
    src = open(PATH, encoding="utf-8").read()
    edits = []  # (start, end, replacement)
    converted, skipped_lit_nomatch = 0, 0
    seen = set()

    for m in CALL_RE.finditer(src):
        name = m.group(1)
        open_idx = m.end() - 1
        close_idx = find_close_paren(src, open_idx)
        if close_idx == -1:
            continue
        value = parse_first_arg_value(src, open_idx, close_idx)
        if value is None:
            continue
        hit = next((p for p in PREFIXES if value.startswith(p)), None)
        if hit is None:
            skipped_lit_nomatch += 1
            continue
        # safety: single-line report for review
        line_no = src.count("\n", 0, m.start()) + 1
        key = (name, value[:40])
        if key in seen:
            continue
        seen.add(key)
        if name == "errors.New":
            repl = "apperr.Validation("
        else:
            repl = "apperr.Validationf("
        edits.append((m.start(1), m.end(1), repl))
        converted += 1

    for start, end, repl in sorted(edits, reverse=True):
        src = src[:start] + repl + src[end:]

    open(PATH, "w", encoding="utf-8", newline="").write(src)
    print(f"converted={converted} distinct-prefix-sites={len(edits)} literal-but-no-match={skipped_lit_nomatch}")


if __name__ == "__main__":
    sys.exit(main())
