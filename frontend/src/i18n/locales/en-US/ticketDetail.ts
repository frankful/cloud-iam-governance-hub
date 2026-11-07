// Ticket detail page copy: actions, alerts, field labels and status wording.
export default {
  ticketDetail: {
    loading: "Loading…",
    // Separator used when joining list items: comma + space in English.
    listSeparator: ", ",
    action: {
      back: "Back",
      submit: "Submit for approval",
      approve: "Approve",
      reject: "Reject",
      retryPublish: "Retry publish",
      rollback: "Start rollback",
      abandon: "Abandon",
      rearm: "Restart polling",
      copy: "Copy",
      cancel: "Cancel",
    },
    // Why the rollback action is disabled (the server rejects these types too).
    rollbackUnsupported: {
      type: "This ticket type cannot be rolled back: its declarations do not live in a single file, so a rollback would not undo anything. Use the matching forward ticket instead (for batch adoption, detach each policy).",
      attach: "An attach ticket has no rollback path: file a detach ticket to remove the attachment.",
    },
    field: {
      type: "Type",
      principal: "Principal",
      submitter: "Submitted by",
      approvalMode: "Approval mode",
      approvalModeAuto: "Automatic",
      approvalModeManual: "Manual",
      approvers: "Approvers",
      pollCount: "Poll attempts",
      gitRepository: "Git repository",
      pr: "PR",
      closureReason: "Closure reason",
      closureComment: "Closure note",
      createdAt: "Created at",
      updatedAt: "Updated at",
    },
    request: {
      title: "Request details",
      operation: {
        attach: "Attach",
        detach: "Detach (destroy the attachment)",
      },
      label: {
        operationType: "Operation",
        targetTicket: "Target ticket",
        sourceTicket: "Source ticket",
        managedPolicy: "Managed policy",
        targetPolicy: "Target policy",
        targetGroup: "Target group",
        roleInlinePolicies: "Role inline policies included in this batch",
        inlinePolicyName: "Inline policy name",
        policyDocument: "Policy document",
      },
      policyDocumentSize: "{{bytes}} bytes (see the Terraform below)",
      detachWarning:
        "Detaching clears the Terraform file of the source attach ticket; terraform plan will destroy that attachment.",
    },
    approval: {
      waiting: "Waiting for approval",
      waitingApprovers: "Waiting for {{approvers}} to approve",
      decidedWaiting: "You {{decision}}; waiting for {{approvers}} to respond",
      allDecided: "All approvers have responded; the ticket is about to be approved",
      noRepeatHint:
        "No further action is needed; the ticket moves on automatically once every named approver has responded.",
      decision: {
        approve: "approved",
        reject: "rejected",
      },
      approved: "Approved",
      rejected: "Rejected",
      pending: "Pending approval",
    },
    approvalRecords: {
      title: "Approval records",
      empty: "No approval records",
      you: "(you)",
    },
    terraform: {
      title: "Terraform code",
      previewBadge: "Preview (the ticket is not published yet)",
      previewDesc:
        "Once the ticket is published, the Terraform file in the PR will match this preview.",
      previewFailed: "Failed to generate the preview: {{error}}",
      empty: "The Terraform file content will be generated here once the ticket is published.",
    },
    poll: {
      stopped: "Polling stopped (the PR was not merged within 7 days)",
      stoppedDesc:
        'The ticket stays in the "Published" state and the PR can still be merged. To keep tracking the merge status, click "Restart polling" to open a new 7-day observation window.',
    },
    applyFailed: {
      title: "Terraform apply failed — the change did not take effect",
      desc: "The PR was merged into the main branch, but CI's terraform apply failed (commit {{commit}}). Nothing was created or changed in AWS, and the ticket stays Published for you to handle: fix and re-run the flow, or close / abandon the ticket.",
      viewCI: "Open CI run",
      noCommit: "unknown",
    },
    pollStatus: {
      title: "Git polling status",
      empty: "No polling records",
      mergeState: "Merge status",
      ci: "CI",
      applyResult: "Apply result",
      attempt: "Poll attempt {{attempt}}",
    },
    mergeState: {
      open: "Open",
      merged: "Merged",
      closed: "Closed",
      locked: "Locked",
      unknown: "Unknown",
    },
    applyResult: {
      pending: "Pending merge",
      succeeded: "Applied",
      failed: "Failed",
      unknown: "Unknown",
    },
    success: {
      submitted: "Submitted for approval",
      abandoned: "Ticket abandoned and closed",
      applied: "Ticket marked as applied and closed",
      publishRetried: "Publish retriggered",
      rearm: "Restarted polling the Git status",
      copied: "Copied to the clipboard",
    },
    error: {
      copyFailed: "Copy failed",
    },
    modal: {
      approveTitle: "Approve ticket",
      rejectTitle: "Reject ticket",
      commentLabel: "Approval comment",
      commentPlaceholder: "Optional",
      abandonTitle: "Abandon this ticket?",
      abandonWarningWithPr:
        "This ticket has already created a PR. If the PR is still open, close it in the code host first; a PR that is already merged cannot be abandoned.",
      abandonWarning: "Abandoning closes the ticket and cannot be undone.",
      abandonCommentPlaceholder: "Reason for abandoning (optional)",
      appliedTitle: "Mark as applied and close",
      appliedWarning:
        "Only use this after you have run terraform apply on the main working copy and verified the result. Closing is terminal; the ticket becomes a rollback target.",
      appliedTriggerSync: "Trigger an inventory sync for the account after closing",
      appliedTriggerSyncHint: "Triggers immediately on close (you confirmed the apply); a sync already in flight is not duplicated.",
      appliedCommentPlaceholder: "Comment (optional, e.g. the apply PR/commit)",
    },
  },
};
