export default {
  users: {

    title: "Users & tokens",
    action: {
      createUser: "New user",
      tokens: "Tokens",
      issueToken: "Issue",
      revokeToken: "Revoke",
      provision: "Provision to cloud",
    },
    column: {
      userId: "User ID",
      displayName: "Name",
      roles: "Roles",
    },
    hint: {
      title: "This screen manages platform identities (the people who sign in), not AWS IAM principals.",
      body: "A token secret is shown once at issuance — hand it to the person over a channel you trust. It lives in the browser session only and is lost when the tab closes.",
    },
    modal: {
      createTitle: "New user",
      editTitle: "Edit user {{id}}",
      tokenTitle: "Tokens · {{id}}",
      tokenTitleGeneric: "Tokens",
    },
    form: {
      userId: "User ID",
      userIdRequired: "Enter a user ID",
      userIdHint: "The platform/SSO subject identifier — it cannot be changed later",
      displayName: "Name",
      displayNameRequired: "Enter a name",
      roleRequired: "Pick at least one role",
      roleHint: "Roles are replaced, not merged: roles you leave unchecked are dropped",
      approverAccounts: "Approver accounts",
      approverAccountsHint:
        "Accounts this user may approve. Same bindings as Sync → Account configurations → Approvers; both views stay in sync.",
      approverAccountsPlaceholder: "Select the accounts this user approves",
    },
    token: {
      defaultName: "admin console",
      issueTitle: "Issue a new token",
      nameRequired: "Enter a token name",
      expiryHours: "Validity (hours)",
      secretTitle: "Token secret (shown only once)",
      secretHint:
        "You cannot see it again once this dialog closes — copy it now and hand it to the person.",
      revoked: "Revoked",
      active: "Active",
      column: {
        prefix: "Prefix",
        expires: "Expires",
        lastUsed: "Last used",
      },
    },
    toast: {
      created: "User created",
      updated: "User updated",
      tokenIssued: "Token issued — the secret is shown only once",
      tokenRevoked: "Token revoked",
    },
    approverWarn: {
      title: "This user is still an approver of {{count}} account(s)",
      content:
        "After deactivation or removing the approver role, account(s) {{accounts}} lose this approver: AUTO ticket creation may fail with no approvers left, and in-flight tickets may become unapprovable. Bind another approver first — under another user's Approver accounts, or under Sync Management → Account Approvers.",
      confirm: "Continue anyway",
    },
    provision: {
      title: "Provision to cloud · {{id}}",
      hint: "Each selected cloud account gets one CREATE_USER ticket (IAM user name = platform user ID) through the normal approval → PR → apply flow; the platform does not manage cloud credentials.",
      accounts: "Target cloud accounts",
      accountsRequired: "Select at least one cloud account",
      disabledFiltered:
        "{{count}} unavailable account(s) hidden (no onboarding config or sync disabled). To provision, enable them first under Sync Management → Accounts.",
      groups: "Initial groups (optional)",
      groupsHint:
        "Only groups present in every selected account are listed; leave empty to join none (adjust later with a group-membership ticket).",
      groupsPlaceholder: "Groups to join on creation",
      groupsPlaceholderNoAccount: "Select cloud accounts first",
      groupsLoadFailed: "Failed to load groups — please retry",
      approvalMode: "Approval mode",
      modeAuto: "AUTO · approvers resolved from account bindings",
      modeManual: "MANUAL · pick approvers yourself",
      approvers: "Approvers",
      approversRequired: "MANUAL mode requires approvers",
      submit: "Create tickets",
      resultsTitle: "Tickets created per account",
      resultsHint: "Failed accounts produced no ticket; fix the error and retry that account.",
      conflictTag: "Name conflict",
      conflictHint:
        "An existing IAM user with the same name is never duplicated or implicitly imported: if it is not managed yet, use New ticket → Create IAM user with \"adopt existing resource\"; if it is already managed, use the matching update ticket.",
      colAccount: "Cloud account",
      colTicket: "Ticket",
      created: "Created",
      toastAll: "All tickets created",
      toastPartial: "{{failed}} account(s) failed — see the list",
    },
  },
};
