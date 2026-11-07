// 漂移页文案：声明快照 vs 线上实态。
// 页面必须把「覆盖范围」和「心跳」写清楚——把「没检测」看成「没问题」
// 是这类页面最常见的误读。
export default {
  drift: {
    title: "漂移发现",
    subtitle:
      "拿「已声明的意图」与同步后的实态逐字段比对。差异不是配置错误，而是「有人绕过了平台，或基线没有跟上」——两条收敛路径都要人工确认。",
    coverageNotice:
      "检测范围只覆盖发布过基线、或被成功工单声明过的资源。未纳管资源不在本页，请到库存页查看。",
    empty: "没有符合条件的漂移发现。",
    unmanaged: "未纳管，不检测",
    action: {
      refresh: "刷新",
      check: "立即检测",
      checkNeedAccount: "请先在左侧选择账号",
      ignore: "忽略",
      reopen: "重新打开",
      resolve: "标记已处置",
      checkConfirmTitle: "立即检测该账号",
      checkConfirmContent:
        "将用当前库存与该账号的全部声明比对一次，并写入/关闭发现。判定通常是秒级。继续？",
      checkDone:
        "检测完成：声明 {{declarations}} 条，新增 {{surfaced}} 条，升级 {{promoted}} 条，自动关闭 {{resolved}} 条。",
    },
    // 收敛双路（设计 §7）。文案必须把「追认 ≠ 回滚」写明白：两件事都改变
    // 现实，但方向和影响面完全不同。
    remediate: {
      acknowledge: "接受现状",
      acknowledgeConfirm:
        "重发该账号的基线：把当前线上状态写成代码。这是追认，不是回滚，会覆盖该账号的全部声明文件并开一个基线 PR。确认继续？",
      rollback: "回滚到声明",
      rollbackConfirm:
        "按声明快照回填一张 UPDATE_* 工单草稿。草稿仍需审批与发布才会生效，不会直接改动 AWS。确认生成？",
      draftCreated: "已生成草稿工单 {{ticketNo}}，请补充说明后提交审批。",
      publicationStarted: "已开始重发基线，请到基线发布页跟踪进度。",
      alreadyPublished: "本次同步已发过基线，无需重发。",
      inFlight: "该账号已有基线发布正在进行，请到基线发布页查看进度。",
    },
    filter: {
      account: "账号",
      status: "状态",
      severity: "严重度",
      includeResolved: "包含已解决",
      managed: "纳管 · {{declarations}} 条声明",
    },
    card: {
      declarations: "声明数",
      open: "未解决",
      stale: "基准过期",
      lastCheck: "上次检测",
      lastClean: "上次全绿",
      never: "从未检测",
    },
    // 覆盖缺口（C7 / C13）：检测跑过但「跳过了一部分」和「压根没跑」都必须
    // 说出来，否则页面上的 0 条发现会被读成「没问题」。
    health: {
      lastCheck: "上次检测 {{time}}",
      neverChecked: "从未检测",
      neverCheckedHint: "该账号已纳管但还没跑过一次检测，0 条发现不代表一致。",
      overdue: "上次检测是 {{time}} —— 已超过 48 小时",
      overdueHint:
        "检测跟随同步执行，长时间不检测通常说明同步没跑（或一直失败）。这里没有发现，不等于实态与声明一致。",
      overdueSummary: "{{count}} 个账号超过 48 小时未检测",
      overdueSummaryHint: "选中账号可看具体时间；同步是否停摆请到「同步管理」核对。",
      skipped: "上轮跳过 {{files}} 个文件",
      skippedHint: "这些文件被在途变更（未合并的 PR / 未关单的工单）占用，本轮未参与比对。",
      staleFiles: "{{files}} 个文件基准已过期",
      staleHint: "基准与 main 的内容不一致（baseline_stale），比对结果可能滞后，建议重发基线。",
      justNow: "刚刚",
      minutesAgo: "{{count}} 分钟前",
      hoursAgo: "{{count}} 小时前",
      daysAgo: "{{count}} 天前",
    },
    column: {
      severity: "严重度",
      account: "账号",
      resource: "资源",
      source: "来源",
      changeType: "类型",
      status: "状态",
      summary: "说明",
      occurrences: "出现次数",
      lastSeen: "最近发现",
      actions: "操作",
    },
    field: {
      name: "字段",
      declared: "声明值",
      live: "实态值",
    },
    status: {
      SUSPECT: "待确认",
      OPEN: "已确认",
      PENDING: "等待生效",
      PENDING_REBASELINE: "基线待更新",
      IGNORED: "已忽略",
    },
    // 来源区分「谁看到的」：库存判定、CI plan、发布冲突。三类差异的可信度
    // 与处置路径不同，混在一起会让人误以为都是同一件事。
    source: {
      inventory: "库存检查",
      ci: "CI 计划",
      publish: "发布冲突",
    },
    changeType: {
      attribute: "属性不一致",
      declared_missing: "声明资源丢失",
      undeclared_extra: "未声明多余资源",
      file_conflict: "文件冲突",
      baseline_stale: "基准过期",
    },
    // 摘要按语义码渲染（C16）：服务端下发的 summary 是中文兜底，旧的发现
    // 没有码，继续显示原文。
    summary: {
      declared_missing: "声明过的 {{resource}} 在线上已不存在",
      undeclared_extra: "{{resource}} 多出一条未声明的{{child}}",
      baseline_stale: "基准过期：{{file}} 在 main 上被改动过，差异不能判定为漂移，请重发基线",
      attribute: "{{resource}} 与声明不一致",
      attribute_fields: "{{resource}} 的 {{fields}} 与声明不一致",
      file_conflict: "{{file}} 的声明被其他发布者占用，需先确认归属",
    },
    // 「多出一条未声明的…」里的子资源名称。
    child: {
      attachment: "策略挂载",
      membership: "组成员",
      inline_policy: "内联策略",
      resource: "资源",
    },
    severity: {
      LOW: "低",
      MEDIUM: "中",
      HIGH: "高",
      CRITICAL: "严重",
    },
    error: {
      load: "漂移列表加载失败",
      accounts: "账号概览加载失败",
      check: "触发检测失败",
      action: "处置失败",
      remediate: "收敛操作失败",
    },
  },
};
