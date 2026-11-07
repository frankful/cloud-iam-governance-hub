export default {
  sync: {

    title: "同步管理",
    accountConfigs: "账号配置",
    selectAccount: "选择账号",
    noAccountConfigs: "暂无账号配置（通过 API 创建后可在此管理）",
    runHistory: "运行历史",
    action: {
      syncNow: "手动同步",
      approvers: "审批人",
    },
    approvers: {
      title: "审批人配置 — {{name}}",
      hint: "AUTO 模式的审批人由这里的绑定决定；未绑定任何审批人的账号无法进入审批流。仅 active 的 platform_admin / approval_admin 可选。",
      empty: "暂无有资格的审批人（需要 active 的 platform_admin / approval_admin）",
      noBinding: "未绑定",
      staleTitle: "以下已绑定用户已失效（停用或不再具备审批角色）",
      staleHint: "保存后这些绑定将被自动移除，请及时补充其他审批人。",
      bound: "已绑定 {{count}} 人",
    },
    trigger: {
      manual: "手动",
      ticketClosed: "关单联动",
    },
    toast: {
      triggered: "同步已触发，正在后台执行",
      enabled: "已启用同步",
      disabled: "已停用同步",
      downloading: "已开始下载清单差集 CSV",
      approversSaved: "审批人配置已保存",
    },
    workerOffline: "同步 worker 未运行",
    workerOfflineHint:
      "触发的同步会排队等待（当前积压 {{count}} 条）。请确认 sync-worker 已启动（本地可用 scripts/dev-up.ps1 一并启动）。",
    mode: "模式：{{mode}}",
    state: "状态",
    lastSuccess: "最近成功：{{time}}",
    lastAttempt: "最近尝试：{{time}}",
    downloadHint: "下载本次同步的清单差集（新增/移除）",
    footer: "同步由后台 sync-worker 进程异步执行（AWS 只读采集）；运行中每 5 秒自动刷新。",
    column: {
      account: "账号",
      trigger: "触发",
      actor: "操作人",
      status: "状态",
      started: "开始",
      finished: "结束",
      changes: "变更",
      error: "错误",
    },
  },
};
