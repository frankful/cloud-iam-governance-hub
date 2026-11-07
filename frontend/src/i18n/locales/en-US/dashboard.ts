// Dashboard copy: overview statistics, the ticket status table and the
// sync/risk breakdown.
export default {
  dashboard: {
    title: "Dashboard",
    action: {
      refresh: "Refresh",
    },
    stat: {
      totalTickets: "Total tickets",
      openRisks: "Open risks",
      iamPrincipals: "IAM principals (users/roles)",
      groups: "Groups",
    },
    card: {
      ticketStatus: "Tickets by status",
      syncOverview: "Sync overview",
    },
    column: {
      status: "Status",
      count: "Count",
    },
    sync: {
      configuredAccounts: "Configured accounts: ",
      enabledCount: " ({{count}} enabled for sync)",
      runsLast24h: "Runs in the last 24 hours: ",
      riskLevels: "Risk levels: ",
    },
    drift: { unresolved: "Unresolved drift: " },
    // Separator between the items of a breakdown list.
    listSeparator: ", ",
    empty: {
      none: "None",
    },
    error: {
      loadFailed: "Failed to load: {{message}}",
    },
  },
};
