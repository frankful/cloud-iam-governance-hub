// 基线页文案：从库存生成多文件 Terraform bundle（含 import 块）。
// tabs 下分「预览」（只读审查）与「发布」（推分支开 PR 全量 import）。
export default {
  baseline: {
    tabs: {
      preview: "基线预览",
      publish: "发布 Import PR",
    },
    title: "基线预览",
    subtitle:
      "从库存生成该账号的完整 Terraform 声明（多文件 + import 块），并检测文件已存在、已被工单纳管、地址重复三类冲突。预览只读，发布在后续步骤执行。",
    filter: { account: "选择账号" },
    create: "生成基线预览",
    createConfirmTitle: "生成基线预览",
    createConfirmContent:
      "将按当前库存生成整账号 Terraform bundle 并落一条 job 记录，通常几秒到几十秒。继续？",
    created: "预览 job #{{id}} 已创建，正在后台构建",
    empty: "还没有预览记录。选择账号后点击「生成基线预览」。",
    error: {
      accounts: "账号列表加载失败",
      create: "创建预览 job 失败",
      list: "预览 job 列表加载失败",
      detail: "预览详情加载失败",
    },
    column: {
      id: "Job",
      status: "状态",
      requestedBy: "发起人",
      files: "文件数",
      issues: "问题数",
      hash: "内容指纹",
      createdAt: "创建时间",
      finishedAt: "完成时间",
      error: "错误",
    },
    status: {
      PENDING: "排队中",
      RUNNING: "构建中",
      COMPLETED: "已完成",
      FAILED: "失败",
    },
    detail: {
      title: "预览 #{{id}}",
      repoDir: "仓库目录",
      counts: {
        files: "文件",
        resources: "资源",
        relationships: "关系",
        "generation-errors": "生成错误",
        "already-declared": "已纳管",
        "files-exist-in-repo": "仓库已有文件",
      },
      hash: "内容指纹",
      hashHint: "同库存同指纹：两次构建指纹不一致说明库存或生成逻辑漂移了",
      filesTitle: "bundle 文件",
      issuesTitle: "冲突与提示",
      noIssues: "没有检测到冲突",
      column: {
        fileName: "文件",
        sources: "来源资源",
        addresses: "Terraform 地址",
        exists: "仓库已有",
        content: "内容",
        kind: "类型",
        detail: "说明",
      },
      // issue 说明按服务端给的 detail_code 取文案（服务端只保留中文原文兜底），
      // 新增一类 issue 时这里与 en-US 要同时补，否则英文界面会退回中文原文。
      issueDetail: {
        "already-declared": "平台已有工单声明过该资源；再写一份会造成同一地址双声明",
        "file-exists": "目标分支已有同名文件，发布时必须走更新而非覆盖",
        "repo-check-failed": "仓库检查失败：{{error}}",
        "file-key-merged": "两个资源落到同一文件，保留前者的内容",
        "file-key-conflict": "多个资源抢同一个文件，只能有一个落进去",
        "address-conflict": "多个资源用同一个 Terraform 地址，plan 会报重复声明",
        "generator-missing": "生成器未实现",
        "generator-error": "生成失败：{{error}}",
        deferred: "文件被其他开放变更占用，本轮让路：{{holder}}",
      },
      relationship: "关系",
      existsYes: "已存在",
      existsNo: "不存在",
      existsUnknown: "未检查",
      issueKind: {
        "file-exists": "文件已存在",
        "already-declared": "已被工单纳管",
        "file-key": "文件 key 冲突",
        address: "地址重复",
        "generation-error": "生成错误",
        deferred: "被占用让路",
      },
      viewContent: "查看内容",
      generationError: "生成失败",
    },
    publish: {
      title: "发布 Import PR",
      subtitle:
        "把该账号的完整 Terraform 声明推送为仓库分支并开 Pull Request，合并到 main 后在 main 执行 plan/apply 完成全量 import。",
      filter: { account: "选择账号" },
      action: "发布基线（全量 Import）",
      confirmTitle: "发布基线到 IaC 仓库",
      // 逐条说明真实行为，别把最坏情况写成默认：多数情况下没有差异，连 PR 都不会开。
      confirmLine1: "按该账号最新一次成功同步的库存快照重建基线，先与仓库 main 逐文件比对。",
      confirmLine2:
        "只推送有差异的文件（每个文件一次提交，约 2 秒/个）；全部一致时不会创建 PR，直接记为「已发布」。",
      confirmLine3:
        "不会覆盖非基线拥有的文件：撞到工单或手工在管的文件会整体失败，并列出冲突清单，同时生成漂移发现。",
      confirmLine4: "同一份快照只发布一次；失败可重试，已写入的文件会自动跳过。",
      // 预检差异数（C10）：数字来自 GET baseline-preview，与发布同一套分类。
      previewCounts:
        "本次共 {{files}} 个文件：{{unchanged}} 个与 main 一致，{{toPublish}} 个需要推送。",
      previewAllSame: "全部 {{files}} 个文件与 main 一致：只会记录发布结果，不会开 PR。",
      previewConflicts:
        "另有 {{count}} 个文件内容不同但不属于基线，发布会被拒绝：{{files}}（超出 5 个只列前 5 个）。",
      previewFailed: "预检差异失败：{{message}}。继续发布仍会自行比对，但不保证结果。",
      confirmOk: "开始发布",
      createdTitle: "发布已开始",
      createdContent:
        "台账 #{{id}} 已创建，正在按快照重建分支 {{branch}} 并与仓库比对；有差异时会自动开 Pull Request，无差异则直接记为已发布",
      alreadyTitle: "该快照已发布过",
      alreadyContent: "台账 #{{id}} 命中幂等键，未重复发布；详情见下方记录",
      publishingHint:
        "发布进行中：先重建基线并与 main 比对，再逐文件提交差异（受 GitHub 限速影响，数百个文件通常 10 分钟左右；无差异则很快完成）。页面会自动刷新",
      hint: "发布即向 IaC 仓库推送全账号 Terraform 声明（含 import 块）",
      hintDetail:
        "合并 PR 到 main 后，在 main 工作副本执行 terraform plan 核对 import 计划，再 apply。基线只更新自己既往发布过的文件；若目标文件已存在且不归基线（工单/手工在管），发布不会覆盖它，而是整体失败并列出冲突清单。",
      empty: "还没有发布记录。选择账号后点击「发布基线（全量 Import）」。",
      error: {
        accounts: "账号列表加载失败",
      },
      status: {
        PUBLISHING: "发布中",
        PUBLISHED: "已发布",
        FAILED: "失败",
        MERGED: "已合入",
        CLOSED: "已关闭",
      },
      column: {
        id: "台账",
        status: "状态",
        branch: "分支",
        pullRequest: "Pull Request",
        files: "文件数",
        hash: "内容指纹",
        requestedBy: "发起人",
        createdAt: "创建时间",
        error: "错误",
      },
      detail: {
        title: "发布台账 #{{id}}",
        branch: "分支",
        syncRun: "库存快照 run",
        repoDir: "仓库目录",
        openPullRequest: "打开 Pull Request #{{number}}",
        mergeHint: "合并到 main 后在 main 执行 terraform plan/apply 完成导入",
        supersededTitle: "历史 PR（重发前的记录）",
        supersededAt: "被替代时间",
      },
    },
  },
};
