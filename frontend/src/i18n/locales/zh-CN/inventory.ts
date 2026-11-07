// 资产清单页文案：清单/主体/用户组的表格、筛选器与详情抽屉。
export default {
  inventory: {
    title: "资产清单",
    action: {
      refresh: "刷新",
      detach: "解绑",
      editInlinePolicy: "编辑内嵌策略",
      editManagedPolicy: "编辑托管策略",
    },
    category: {
      ticket: "用户自定义",
      aws: "官方托管",
    },
    officialTag: "官方托管",
    selectAccountFirst: "请先选择账号后查看资产",
    tab: {
      principals: "IAM 主体",
      users: "用户",
      roles: "角色",
      groups: "用户组",
      policies: "自管策略",
      inline: "内联策略",
      profiles: "实例配置文件",
    },
    eksManagedTip: "EKS 托管节点组自动创建（eks-<uuid>）；节点组重建会换新名，删除节点组时连带删除",

    filter: {
      allAccounts: "全部账号",
      selectAccount: "请选择账号（必选）",
      searchPlaceholder: "名称 / ARN 模糊搜索",
    },
    account: {
      unnamed: "未命名",
      option: "{{id}}（{{name}}）",
    },
    column: {
      name: "名称",
      type: "类型",
      awsAccount: "AWS 账号",
      arn: "ARN",
      lastSynced: "最近同步",
      groupName: "组名",
      memberCount: "成员数",
      policyName: "策略名",
      owner: "所属主体",
      ownerArn: "主体 ARN",
      profileName: "配置文件名",
      boundRole: "绑定角色",
      path: "路径",
    },
    drawer: {
      trustPolicy: "信任策略",
      policyDocument: "策略文档",
      attachedPrincipals: "挂载主体数",
      attachedGroups: "挂载组数",
      tags: "标签",
      attachedPolicies: "直挂策略",
      groups: "所属组",
      groupMembers: "组成员",
      groupPolicies: "组策略",
      memberCountLabel: "成员数：",
    },
    empty: {
      none: "无",
      noMembers: "无成员",
      documentNotFetched: "尚未拉取——挂载该策略时会自动获取文档。",
    },
    error: {
      loadFailed: "加载清单失败：{{message}}",
      detailFailed: "加载详情失败：{{message}}",
    },
  },
};
