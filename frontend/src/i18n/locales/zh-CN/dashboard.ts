// 仪表盘页面文案：概览统计卡片、工单状态分布表与同步/风险概况。
export default {
  dashboard: {
    title: "Dashboard",
    action: {
      refresh: "刷新",
    },
    stat: {
      totalTickets: "工单总数",
      openRisks: "未决风险",
      iamPrincipals: "IAM 主体（用户/角色）",
      groups: "用户组",
    },
    card: {
      ticketStatus: "工单状态分布",
      syncOverview: "同步概况",
    },
    column: {
      status: "状态",
      count: "数量",
    },
    sync: {
      configuredAccounts: "已配置账号：",
      enabledCount: "（启用同步 {{count}}）",
      runsLast24h: "最近 24 小时运行：",
      riskLevels: "风险等级：",
    },
    drift: { unresolved: "未解决漂移：" },
    // 概况列表中各项之间的分隔符（中文用顿号式逗号，英文用逗号加空格）。
    listSeparator: "，",
    empty: {
      none: "无",
    },
    error: {
      loadFailed: "加载失败：{{message}}",
    },
  },
};
