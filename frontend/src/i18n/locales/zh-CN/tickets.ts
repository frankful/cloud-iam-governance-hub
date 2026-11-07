// 工单列表页面文案：标题、筛选条件、表格列、状态与类型标签。
export default {
  tickets: {
    title: "工单中心",
    action: {
      create: "新建工单",
      refresh: "刷新",
    },
    filter: {
      status: "状态",
      type: "类型",
      keyword: "工单号 / 主体名",
      submitter: "提交人",
    },
    column: {
      ticketNo: "工单号",
      status: "状态",
      type: "类型",
      principal: "主体",
      submitter: "提交人",
      approvalMode: "审批模式",
      createdAt: "创建时间",
    },
    // 工单状态：键为后端枚举值，仅用于筛选下拉与标签展示。
    status: {
      DRAFT: "草稿",
      APPROVING: "审批中",
      APPROVED: "已批准",
      PUBLISHING: "发布中",
      PUBLISH_FAILED: "发布失败",
      REJECTED: "已拒绝",
      MERGED: "已合入",
      CLOSED: "已关闭",
    },
    // 工单类型：键为后端枚举值，与新建工单页的类型取值保持一致。
    type: {
      CREATE_ROLE: "创建角色",
      CREATE_MANAGED_POLICY: "创建托管策略",
      CREATE_USER: "创建用户",
      CREATE_GROUP: "创建用户组",
      UPDATE_ROLE: "更新角色",
      ATTACH_USER_POLICY: "挂载/解绑策略",
      UPDATE_MANAGED_POLICY: "更新托管策略",
      UPDATE_GROUP_INLINE_POLICY: "更新内嵌策略",
      UPDATE_GROUP_MEMBERSHIP: "组成员变更",
      ADOPT_ROLE_INLINE_POLICIES: "批量纳管角色内嵌策略",
      ROLLBACK: "回滚",
    },
    approvalMode: {
      auto: "自动",
      manual: "人工",
    },
    error: {
      loadFailed: "加载失败：{{message}}",
    },
  },
};
