export default {
  sync: {

    title: "Sync",
    accountConfigs: "Account configurations",
    selectAccount: "Select account",
    noAccountConfigs: "No cloud accounts yet — onboard one under Account admin",
    runHistory: "Run history",
    action: {
      syncNow: "Sync now",
      approvers: "Approvers",
    },
    approvers: {
      title: "Approvers — {{name}}",
      hint: "AUTO approval resolves its approvers from these bindings; an account without bindings cannot enter the approval flow. Only active platform_admin / approval_admin users are selectable.",
      empty: "No eligible approvers (requires active platform_admin / approval_admin)",
      noBinding: "Not bound",
      bound: "{{count}} bound",
      staleTitle: "The following bound users are no longer eligible (deactivated or missing approver roles)",
      staleHint: "Saving removes these bindings automatically; add other approvers to keep the account usable.",
    },
    trigger: {
      manual: "Manual",
      ticketClosed: "Ticket closed",
    },
    toast: {
      triggered: "Sync triggered; it runs in the background",
      enabled: "Sync enabled",
      disabled: "Sync disabled",
      downloading: "Downloading the inventory diff CSV",
      approversSaved: "Approver configuration saved",
    },
    workerOffline: "The sync worker is not running",
    workerOfflineHint:
      "Triggered syncs queue up ({{count}} pending). Make sure sync-worker is running (scripts/dev-up.ps1 starts it locally).",
    mode: "Mode: {{mode}}",
    state: "Status",
    lastSuccess: "Last success: {{time}}",
    lastAttempt: "Last attempt: {{time}}",
    downloadHint: "Download the inventory diff of this run (added / removed)",
    footer:
      "Syncs run asynchronously in the background sync-worker process (read-only collection from AWS); the view refreshes every 5 seconds while a run is in flight.",
    column: {
      account: "Account",
      trigger: "Trigger",
      actor: "Actor",
      status: "Status",
      started: "Started",
      finished: "Finished",
      changes: "Changes",
      error: "Error",
    },
  },
};
