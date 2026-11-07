export default {
  status: {

    pollExpired: "轮询已过期",
    display: {
      DRAFT: "草稿",
      APPROVING: "审批中",
      APPROVED: "已批准",
      PUBLISHING: "发布中",
      PUBLISHED: "已发布",
      PUBLISH_FAILED: "发布失败",
      REJECTED: "已拒绝",
      MERGED: "已合入",
      CLOSED_APPLIED: "已生效关闭",
      CLOSED_ABANDONED: "已废弃关闭",
    },
    ticketType: {
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
  },
};
