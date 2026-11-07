// Baseline page copy: multi-file Terraform bundle (with import blocks)
// generated from the inventory. Tabs: preview (read-only review) and
// publish (push branch + open PR for full import).
export default {
  baseline: {
    tabs: {
      preview: "Baseline preview",
      publish: "Publish import PR",
    },
    title: "Baseline preview",
    subtitle:
      "Generate the account's full Terraform declaration (multi-file + import blocks) from the inventory and detect three conflict classes: file already exists, already declared by a ticket, duplicate address. Read-only; publication happens later.",
    filter: { account: "Select account" },
    create: "Generate baseline preview",
    createConfirmTitle: "Generate baseline preview",
    createConfirmContent:
      "This builds the account-wide Terraform bundle from the current inventory and records a job. It usually takes seconds. Continue?",
    created: "Preview job #{{id}} created; building in the background",
    empty:
      "No preview yet. Pick an account and click \"Generate baseline preview\".",
    error: {
      accounts: "Failed to load accounts",
      create: "Failed to create the preview job",
      list: "Failed to load preview jobs",
      detail: "Failed to load preview details",
    },
    column: {
      id: "Job",
      status: "Status",
      requestedBy: "Requested by",
      files: "Files",
      issues: "Issues",
      hash: "Content hash",
      createdAt: "Created",
      finishedAt: "Finished",
      error: "Error",
    },
    status: {
      PENDING: "Pending",
      RUNNING: "Building",
      COMPLETED: "Completed",
      FAILED: "Failed",
    },
    detail: {
      title: "Preview #{{id}}",
      repoDir: "Repository directory",
      counts: {
        files: "Files",
        resources: "Resources",
        relationships: "Relationships",
        "generation-errors": "Generation errors",
        "already-declared": "Already declared",
        "files-exist-in-repo": "Files in repo",
      },
      hash: "Content hash",
      hashHint:
        "Same inventory, same hash: a differing hash between two builds means the inventory or the generator drifted",
      filesTitle: "Bundle files",
      issuesTitle: "Conflicts & notices",
      noIssues: "No conflicts detected",
      column: {
        fileName: "File",
        sources: "Sources",
        addresses: "Terraform address",
        exists: "In repo",
        content: "Content",
        kind: "Kind",
        detail: "Detail",
      },
      // Keyed by the server's detail_code; keep in sync with zh-CN, otherwise the
      // English UI falls back to the server's Chinese sentence.
      issueDetail: {
        "already-declared":
          "A ticket already declares this resource; a second declaration would duplicate the same address",
        "file-exists":
          "A file with the same name already exists on the target branch; publishing updates it instead of overwriting",
        "repo-check-failed": "Repository check failed: {{error}}",
        "file-key-merged": "Two resources map to the same file; the first one's content is kept",
        "file-key-conflict": "Several resources claim the same file; only one can land in it",
        "address-conflict": "Several resources share one Terraform address; plan reports a duplicate declaration",
        "generator-missing": "No generator implemented for this resource yet",
        "generator-error": "Generation failed: {{error}}",
        deferred: "Held by another open change, deferred this round: {{holder}}",
      },
      relationship: "Relationship",
      existsYes: "Exists",
      existsNo: "Missing",
      existsUnknown: "Not checked",
      issueKind: {
        "file-exists": "File exists",
        "already-declared": "Already declared",
        "file-key": "File key conflict",
        address: "Duplicate address",
        "generation-error": "Generation error",
        deferred: "Deferred",
      },
      viewContent: "View content",
      generationError: "Generation failed",
    },
    publish: {
      title: "Publish import PR",
      subtitle:
        "Push the account's full Terraform declaration to a repository branch and open a Pull Request; after merging to main, run plan/apply on main to complete the full import.",
      filter: { account: "Select account" },
      action: "Publish baseline (full import)",
      confirmTitle: "Publish baseline to the IaC repository",
      // Spell out the actual behaviour instead of the worst case: most runs have
      // nothing to push and never open a PR at all.
      confirmLine1:
        "Rebuilds the baseline from the account's latest successful sync snapshot, then compares it file by file with main.",
      confirmLine2:
        "Only files that differ are pushed (one commit per file, about 2s each); when everything already matches, no PR is opened and the run is simply recorded as published.",
      confirmLine3:
        "Files the baseline does not own are never overwritten: hitting a ticket-managed or hand-written file fails the whole run, lists the conflicts, and records drift findings.",
      confirmLine4:
        "Each snapshot is published once; a failed run can be retried and already-written files are skipped automatically.",
      previewCounts:
        "{{files}} file(s) in this bundle: {{unchanged}} already match main, {{toPublish}} to push.",
      previewAllSame: "All {{files}} file(s) match main: the run is recorded but no PR is opened.",
      previewConflicts:
        "{{count}} other file(s) differ but are not owned by the baseline; publishing will be refused: {{files}} (first 5 shown).",
      previewFailed: "Could not preview the diff: {{message}}. Publishing will still compare on its own, with no guarantee.",
      confirmOk: "Start publishing",
      createdTitle: "Publishing started",
      createdContent:
        "Ledger #{{id}} created; rebuilding branch {{branch}} and comparing it with the repository. A Pull Request opens automatically when files differ; an identical run is recorded as published",
      alreadyTitle: "Snapshot already published",
      alreadyContent:
        "Ledger #{{id}} hit the idempotency key; nothing was re-published. See the record below",
      publishingHint:
        "Publishing in progress: the bundle is rebuilt and compared with main first, then only differing files are committed (throttled by GitHub, usually ~10 minutes for hundreds of files; an identical run finishes quickly). The page refreshes automatically",
      hint: "Publishing pushes the account-wide Terraform declaration (with import blocks) to the IaC repository",
      hintDetail:
        "After merging the PR to main, run terraform plan on the main working copy to review the import plan, then apply. The baseline only updates files it published before; a file that already exists but is not owned by the baseline (ticket-managed or hand-written) is never overwritten — the run fails as a whole and lists the conflicts.",
      empty:
        "No publications yet. Select an account and click \"Publish baseline (full import)\".",
      error: {
        accounts: "Failed to load accounts",
      },
      status: {
        PUBLISHING: "Publishing",
        PUBLISHED: "Published",
        FAILED: "Failed",
        MERGED: "Merged",
        CLOSED: "Closed",
      },
      column: {
        id: "Ledger",
        status: "Status",
        branch: "Branch",
        pullRequest: "Pull Request",
        files: "Files",
        hash: "Content hash",
        requestedBy: "Requested by",
        createdAt: "Created",
        error: "Error",
      },
      detail: {
        title: "Publication #{{id}}",
        branch: "Branch",
        syncRun: "Inventory snapshot run",
        repoDir: "Repo directory",
        openPullRequest: "Open Pull Request #{{number}}",
        mergeHint:
          "After merging to main, run terraform plan/apply on main to complete the import",
        supersededTitle: "Superseded PRs (before republish)",
        supersededAt: "Superseded at",
      },
    },
  },
};
