// Inventory page strings: tables, filters and the detail drawer.
export default {
  inventory: {
    title: "Asset Inventory",
    action: {
      refresh: "Refresh",
      detach: "Detach",
      editInlinePolicy: "Edit Inline Policy",
      editManagedPolicy: "Edit Managed Policy",
    },
    category: {
      ticket: "Customer-managed",
      aws: "AWS-managed",
    },
    officialTag: "AWS-managed",
    selectAccountFirst: "Select an account to browse assets",
    tab: {
      principals: "IAM Principals",
      users: "Users",
      roles: "Roles",
      groups: "User Groups",
      policies: "Managed Policies",
      inline: "Inline Policies",
      profiles: "Instance Profiles",
    },
    eksManagedTip: "Created by an EKS managed node group (eks-<uuid>); node group rebuilds mint a new name and deletes remove it",

    filter: {
      allAccounts: "All accounts",
      selectAccount: "Select an account (required)",
      searchPlaceholder: "Search by name / ARN",
    },
    account: {
      unnamed: "Unnamed",
      option: "{{id}} ({{name}})",
    },
    column: {
      name: "Name",
      type: "Type",
      awsAccount: "AWS Account",
      arn: "ARN",
      lastSynced: "Last Synced",
      groupName: "Group Name",
      memberCount: "Members",
      policyName: "Policy",
      owner: "Owner",
      ownerArn: "Owner ARN",
      profileName: "Profile",
      boundRole: "Bound Role",
      path: "Path",
    },
    drawer: {
      trustPolicy: "Trust Policy",
      policyDocument: "Policy Document",
      attachedPrincipals: "Attached principals",
      attachedGroups: "Attached groups",
      tags: "Tags",
      attachedPolicies: "Attached Policies",
      groups: "Member Of Groups",
      groupMembers: "Group Members",
      groupPolicies: "Group Policies",
      memberCountLabel: "Members: ",
    },
    empty: {
      none: "None",
      noMembers: "No members",
      documentNotFetched: "Not fetched yet — the document is pulled when this policy is attached.",
    },
    error: {
      loadFailed: "Failed to load the inventory: {{message}}",
      detailFailed: "Failed to load the details: {{message}}",
    },
  },
};
