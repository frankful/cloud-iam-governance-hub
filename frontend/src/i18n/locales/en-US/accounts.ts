// Account admin page copy: onboard / edit / disable cloud account connections.
// Security stance: the platform never stores target-account credentials;
// they come from the collector identity or a cross-account read-only role.
// NOTE: never define a top-level nav here — slices are merged with spread and
// would clobber common's nav wholesale.
export default {
  accounts: {
    title: "Account admin",
    create: "Add account",
    createTitle: "Add cloud account",
    editTitle: "Edit cloud account",
    saved: "Account configuration saved",
    created: "Account onboarded and connectivity verified",
    saveFailed: "Save failed — server-side connectivity check did not pass",
    testOk: "Connectivity OK: identity {{account}} ({{arn}})",
    enabledMsg: "Sync enabled",
    disabledMsg: "Sync disabled (configuration kept, can be re-enabled anytime)",
    empty: "No cloud account onboarded yet. Click \"Add account\" to get started.",
    securityTitle: "Credential security boundary",
    securityHint:
      "This platform never stores cloud account access keys (AK/SK). Multi-account access uses cross-account read-only roles (ASSUME_ROLE): create a read-only IAM role in each target account and trust the collector account. The only secret to safeguard is the collector's own identity, held by the deployment environment (env / secret manager) and never stored in the platform database.",
    noSecretHint:
      "The platform stores no secrets: to rotate collector credentials, update them in the deployment environment (worker env), not on this page.",
    lastSuccess: "last success {{time}}",
    column: {
      account: "Account",
      mode: "Access mode",
      roleArn: "Read-only role ARN",
      enabled: "Enabled",
      syncState: "Sync state",
    },
    mode: {
      assumeRole: "ASSUME_ROLE (cross-account read-only role, recommended)",
      currentCredentials: "CURRENT_CREDENTIALS (collector direct)",
    },
    field: {
      accountId: "Cloud account ID",
      accountIdPattern: "Must be exactly 12 digits",
      accountIdFixed: "Account ID cannot be changed after creation",
      displayName: "Display name",
      displayNamePlaceholder: "e.g. prod-main",
      syncMode: "Access mode",
      roleArn: "Read-only role ARN",
      roleArnHint:
        "Must be an IAM role ARN within this account; sync and connectivity checks only use its read-only permissions.",
      syncEnabled: "Enable sync",
    },
    action: {
      test: "Test",
    },
  },
};
