// Copy for the cleanup page: what the platform declared by mistake and what AWS left behind.
export default {
  cleanup: {
    title: "Cleanup list",
    subtitle:
      "Resources the platform declared by mistake, and resources AWS left behind. Read-only: deletions happen in the IaC repository and in the AWS console; the platform only supplies evidence and exact commands.",
    filter: {
      account: "Select account",
    },
    snapshot: "Inventory snapshot: sync run #{{run}}",
    stat: {
      platformFile: "Declaration files to delete",
      awsResource: "AWS resources to delete",
      high: "Safe to execute",
      review: "Needs review",
    },
    category: {
      "platform-file": "Delete declaration",
      "aws-resource": "Delete AWS resource",
    },
    confidence: {
      high: "Safe to execute",
      review: "Needs review",
    },
    kind: {
      role: "IAM role",
      user: "IAM user",
      group: "IAM group",
      policy: "Customer-managed policy",
      "instance-profile": "Instance profile",
      "oidc-provider": "OIDC provider",
      "saml-provider": "SAML provider",
    },
    column: {
      category: "Category",
      confidence: "Confidence",
      kind: "Type",
      name: "Resource",
      reason: "Why delete",
    },
    detail: {
      evidence: "Evidence",
      action: "Suggested action",
      pr: "Related PR",
    },
    empty: "Nothing to clean up",
    gaps: {
      title: "What this list cannot cover",
    },
    // ---- Translations keyed by the server's reason_code / action_code /
    // evidence.code. The server also ships the original text; the frontend
    // falls back to it when a key is missing, so the two sides evolve
    // independently.
    reason: {
      "platform-file": "The platform generated a declaration for it, but AWS services own its lifecycle, so the declaration cannot hold",
      "profile-no-role": "The instance profile has no role attached and is an empty shell",
      "profile-role-gone": "The role bound to this instance profile no longer exists in the account",
      "profile-eks-review": "The bound role has {{group_size}} EKS-created instance profiles; only one can be in use, and this is one of them",
      "profile-eks-unused": "A sibling instance profile on the same role is confirmed in use; this one is referenced by no launch template",
      "profile-eks-unused-role-idle": "No instance profile on this role is referenced by any launch template, and the role has no nodegroup either",
      "profile-eks-orphan": "This EKS-created instance profile is referenced by no launch template and its role has no nodegroup — a leftover from nodegroup rebuilds",
      "profile-eks-ambiguous": "The bound role is still used by a nodegroup, but this profile is referenced by no launch template: the nodegroup may have just been rebuilt and the evidence is not aligned yet",
      "group-empty-plain": "The group has no members and no attached policies — a pure empty shell",
      "group-empty-policies": "The group has no members but still has policies attached: it may be provisioned ahead of use, or simply never cleaned up",
      "user-orphan-plain": "The user belongs to no group and has no directly attached or inline policies — an orphaned user",
      "user-orphan-policies": "The user belongs to no group but has policies attached or inlined: it may be an independently authorized account, confirm before deleting",
    },
    action: {
      "delete-file": "Delete the declaration file from the IaC repository and archive the ticket; leave the AWS resource untouched",
      "delete-profile": "aws iam delete-instance-profile --instance-profile-name {{name}}",
      "delete-profile-verify": "Confirm which profile is in use via aws eks describe-nodegroup and launch templates first, then delete the rest with aws iam delete-instance-profile",
      "delete-group": "aws iam delete-group --group-name {{name}}",
      "delete-group-detach": "After confirming it is unused, detach the policies first, then: aws iam delete-group --group-name {{name}}",
      "delete-user": "After confirming there are no active access keys: aws iam delete-user --user-name {{name}}",
      "delete-user-detach": "After confirming it is unused, delete its policies first, then: aws iam delete-user --user-name {{name}}",
    },
    evidence: {
      "baseline-reason": "{{reason}}",
      ticket: "Platform ticket {{ticket}} ({{type}} / {{status}})",
      "pr-merged": "Merged PR: {{pr}}",
      "pr-missing": "The ticket has no linked PR: the file may exist only as a draft or was written manually",
      file: "Declaration file: {{file}}",
      "no-role-arn": "role_arn is empty",
      "role-arn": "Bound role: {{arn}}",
      "role-missing": "The role cannot be found in the inventory (it may have been deleted)",
      siblings: "{{count}} instance profiles on the same role: {{names}}",
      others: "Others: {{names}}",
      "eks-rebuild-note": "EKS creates a new UUID-named instance profile on every managed nodegroup rebuild and never cleans up the old ones",
      "in-use": "In use: {{names}} (referenced by a launch template)",
      "role-nodegroups": "The role is still used by nodegroups: {{nodegroups}}",
      "usage-unavailable": "EKS/EC2 evidence unavailable (details in the original text)",
      "group-stats": "{{members}} members; {{policies}} attached policies",
      "user-stats": "{{memberships}} groups; {{policies}} attached/inline policies",
    },
    error: {
      accounts: "Failed to load AWS accounts",
    },
  },
};
