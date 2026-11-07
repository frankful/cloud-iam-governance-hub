export default {
  status: {

    pollExpired: "Polling budget exhausted",
    display: {
      DRAFT: "Draft",
      APPROVING: "Awaiting approval",
      APPROVED: "Approved",
      PUBLISHING: "Publishing",
      PUBLISHED: "Published",
      PUBLISH_FAILED: "Publish failed",
      REJECTED: "Rejected",
      MERGED: "Merged",
      CLOSED_APPLIED: "Closed (applied)",
      CLOSED_ABANDONED: "Closed (abandoned)",
    },
    ticketType: {
      CREATE_ROLE: "Create role",
      CREATE_MANAGED_POLICY: "Create managed policy",
      CREATE_USER: "Create user",
      CREATE_GROUP: "Create group",
      UPDATE_ROLE: "Update role",
      ATTACH_USER_POLICY: "Attach / detach policy",
      UPDATE_MANAGED_POLICY: "Update managed policy",
      UPDATE_GROUP_INLINE_POLICY: "Update inline policy",
      UPDATE_GROUP_MEMBERSHIP: "Group membership change",
      ADOPT_ROLE_INLINE_POLICIES: "Adopt role inline policies",
      ROLLBACK: "Rollback",
    },
  },
};
