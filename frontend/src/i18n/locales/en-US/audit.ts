export default {
  audit: {

    title: "Audit",
    action: {
      export: "Export",
    },
    filter: {
      actor: "Actor",
      action: "Action (e.g. {{example}})",
      outcome: "Outcome",
    },
    outcome: {
      success: "Success",
      failure: "Failure",
    },
    column: {
      time: "Time",
      actor: "Actor",
      action: "Action",
      resource: "Resource",
      resourceId: "Resource ID",
      outcome: "Outcome",
    },
    footer: "Audit events are append-only; the export itself is recorded as well.",
    toast: {
      exported: "Exported (the export was recorded as an audit event)",
    },
  },
};
