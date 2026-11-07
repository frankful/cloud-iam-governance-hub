export default {
  audit: {

    title: "审计",
    action: {
      export: "导出",
    },
    filter: {
      actor: "操作人",
      action: "动作（如 {{example}}）",
      outcome: "结果",
    },
    outcome: {
      success: "成功",
      failure: "失败",
    },
    column: {
      time: "时间",
      actor: "操作人",
      action: "动作",
      resource: "资源",
      resourceId: "资源 ID",
      outcome: "结果",
    },
    footer: "审计事件为追加写入（append-only），导出操作本身也会被记录。",
    toast: {
      exported: "导出成功（已记录审计事件）",
    },
  },
};
