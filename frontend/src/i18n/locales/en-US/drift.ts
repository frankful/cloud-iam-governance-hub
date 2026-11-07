// Drift page copy: declared intent vs live state.
// The page must state its coverage and heartbeat explicitly — reading
// "not checked" as "no problems" is the classic failure of this kind of page.
export default {
  drift: {
    title: "Drift findings",
    subtitle:
      "Compares declared intent with the live state after each sync. A difference is not a broken config — it means someone bypassed the platform or the baseline fell behind; both convergence paths need a human decision.",
    coverageNotice:
      "Only resources declared by a baseline or a successful ticket are covered. Unmanaged resources are not listed here; see Inventory.",
    empty: "No drift findings match the filters.",
    unmanaged: "Not managed, not checked",
    action: {
      refresh: "Refresh",
      check: "Check now",
      checkNeedAccount: "Select an account first",
      ignore: "Ignore",
      reopen: "Reopen",
      resolve: "Mark handled",
      checkConfirmTitle: "Check this account now",
      checkConfirmContent:
        "Compares the current inventory with every declaration of this account and writes or closes findings. Usually takes seconds. Continue?",
      checkDone:
        "Check finished: {{declarations}} declarations, {{surfaced}} new, {{promoted}} promoted, {{resolved}} auto-resolved.",
    },
    // Convergence has two paths, and the copy must keep "accept" and
    // "roll back" apart: both change reality, in opposite directions.
    remediate: {
      acknowledge: "Accept as-is",
      acknowledgeConfirm:
        "Re-publishes this account's baseline: the live state becomes the code. This is an acceptance, not a rollback — it overwrites every declared file of the account and opens a baseline PR. Continue?",
      rollback: "Roll back to declaration",
      rollbackConfirm:
        "Prefills an UPDATE_* ticket draft from the declaration snapshot. The draft still needs approval and publication before anything changes in AWS. Create it?",
      draftCreated: "Draft ticket {{ticketNo}} created; add a description and submit it for approval.",
      publicationStarted: "Baseline re-publication started; follow it on the baseline publication page.",
      alreadyPublished: "This sync run already published a baseline; nothing to re-publish.",
      inFlight: "A baseline publication for this account is already running; follow it on the publication page.",
    },
    filter: {
      account: "Account",
      status: "Status",
      severity: "Severity",
      includeResolved: "Include resolved",
      managed: "Managed · {{declarations}} declarations",
    },
    card: {
      declarations: "Declarations",
      open: "Unresolved",
      stale: "Stale baseline",
      lastCheck: "Last check",
      lastClean: "Last clean",
      never: "Never checked",
    },
    // Coverage gaps (C7 / C13): "checked but skipped some files" and "never
    // checked" both have to be visible, otherwise 0 findings reads as clean.
    health: {
      lastCheck: "Last check {{time}}",
      neverChecked: "Never checked",
      neverCheckedHint:
        "This account is managed but has never been evaluated — 0 findings does not mean it matches.",
      overdue: "Last check was {{time}} — over 48 hours ago",
      overdueHint:
        "Evaluation runs with the inventory sync. No check for this long usually means the sync is not running (or keeps failing). No findings here is not proof of a clean state.",
      overdueSummary: "{{count}} account(s) not checked for over 48 hours",
      overdueSummaryHint:
        "Pick an account to see its timestamp; check Sync to see whether the sync has stalled.",
      skipped: "{{files}} file(s) skipped last round",
      skippedHint:
        "These files are held by in-flight changes (an unmerged PR or an open ticket) and were not compared this round.",
      staleFiles: "{{files}} file(s) with a stale baseline",
      staleHint:
        "The baseline no longer matches main (baseline_stale); comparisons may lag. Republishing the baseline is advisable.",
      justNow: "just now",
      minutesAgo: "{{count}} min ago",
      hoursAgo: "{{count}} h ago",
      daysAgo: "{{count}} d ago",
    },
    column: {
      severity: "Severity",
      account: "Account",
      resource: "Resource",
      source: "Source",
      changeType: "Type",
      status: "Status",
      summary: "Summary",
      occurrences: "Seen",
      lastSeen: "Last seen",
      actions: "Actions",
    },
    field: {
      name: "Field",
      declared: "Declared",
      live: "Live",
    },
    status: {
      SUSPECT: "Suspect",
      OPEN: "Open",
      PENDING: "Pending apply",
      PENDING_REBASELINE: "Rebaseline",
      IGNORED: "Ignored",
    },
    // Where the finding came from: inventory comparison, CI plan, or a
    // publication conflict. Their trust level and remedy differ.
    source: {
      inventory: "Inventory check",
      ci: "CI plan",
      publish: "Publish conflict",
    },
    changeType: {
      attribute: "Attribute mismatch",
      declared_missing: "Declared but missing",
      undeclared_extra: "Undeclared extra",
      file_conflict: "File conflict",
      baseline_stale: "Stale baseline",
    },
    // Summaries render from the server-side code (C16); older findings carry
    // no code and keep showing the raw server text.
    summary: {
      declared_missing: "Declared {{resource}} no longer exists in the account",
      undeclared_extra: "{{resource}} has an undeclared {{child}}",
      baseline_stale:
        "Stale baseline: {{file}} was changed on main, so the difference cannot be classified as drift. Re-publish the baseline",
      attribute: "{{resource}} no longer matches its declaration",
      attribute_fields: "{{resource}} differs from its declaration in {{fields}}",
      file_conflict: "{{file}} is owned by another publisher; confirm ownership first",
    },
    // Names used inside "has an undeclared …".
    child: {
      attachment: "policy attachment",
      membership: "group membership",
      inline_policy: "inline policy",
      resource: "resource",
    },
    severity: {
      LOW: "Low",
      MEDIUM: "Medium",
      HIGH: "High",
      CRITICAL: "Critical",
    },
    error: {
      load: "Failed to load drift findings",
      accounts: "Failed to load account overview",
      check: "Failed to trigger the check",
      action: "Failed to apply the action",
      remediate: "Failed to converge the finding",
    },
  },
};
