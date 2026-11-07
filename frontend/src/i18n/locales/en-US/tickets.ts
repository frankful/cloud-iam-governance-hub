// Ticket list copy: title, filters, table columns, status and type labels.
export default {
  tickets: {
    title: "Tickets",
    action: {
      create: "New ticket",
      refresh: "Refresh",
    },
    filter: {
      status: "Status",
      type: "Type",
      keyword: "Ticket no. / principal name",
      submitter: "Submitter",
    },
    column: {
      ticketNo: "Ticket no.",
      status: "Status",
      type: "Type",
      principal: "Principal",
      submitter: "Submitter",
      approvalMode: "Approval mode",
      createdAt: "Created at",
    },
    // Ticket status: keys are the backend enum values, used by the filter
    // dropdown and the status labels.
    status: {
      DRAFT: "Draft",
      APPROVING: "Approving",
      APPROVED: "Approved",
      PUBLISHING: "Publishing",
      PUBLISH_FAILED: "Publish failed",
      REJECTED: "Rejected",
      MERGED: "Merged",
      CLOSED: "Closed",
    },
    // Ticket type: keys are the backend enum values, aligned with the ticket
    // types offered on the new ticket page.
    type: {
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
    approvalMode: {
      auto: "Auto",
      manual: "Manual",
    },
    error: {
      loadFailed: "Failed to load: {{message}}",
    },
  },
};
