// 账号管理页文案：录入/编辑/停用云账号接入配置。
// 安全口径：平台永不存储目标账号密钥，凭证只来自收集者身份或跨账只读角色。
// 注意：这里不能定义顶层 nav——切片按 ...spread 合并，会整体覆盖 common 的 nav。
export default {
  accounts: {
    title: "账号管理",
    create: "录入账号",
    createTitle: "录入云账号",
    editTitle: "编辑云账号",
    saved: "账号配置已保存",
    created: "账号已录入并连通",
    saveFailed: "保存失败——服务端连通性校验未通过",
    testOk: "连通正常：身份 {{account}}（{{arn}}）",
    enabledMsg: "已启用同步",
    disabledMsg: "已停用同步（账号配置保留，可随时重新启用）",
    empty: "还没有接入任何云账号。点击右上角「录入账号」开始接入。",
    securityTitle: "密钥安全边界",
    securityHint:
      "本平台不存储任何云账号的访问密钥（AK/SK）。多账号接入走跨账只读角色（ASSUME_ROLE）：在每个目标账号创建只读 IAM 角色并授权给收集者账号；唯一需要保管的秘密是收集者自身的身份，由部署环境（env/密钥管理服务）持有，不进入平台数据库。",
    noSecretHint:
      "平台不保存任何密钥：如需更换收集者凭证，请在部署环境（worker 的 env）中更新，不在本页操作。",
    lastSuccess: "上次成功 {{time}}",
    column: {
      account: "账号",
      mode: "接入模式",
      roleArn: "跨账只读角色 ARN",
      enabled: "启用",
      syncState: "同步状态",
    },
    mode: {
      assumeRole: "ASSUME_ROLE（跨账只读角色，多账号推荐）",
      currentCredentials: "CURRENT_CREDENTIALS（收集者直连）",
    },
    field: {
      accountId: "云账号 ID",
      accountIdPattern: "必须是 12 位数字",
      accountIdFixed: "账号 ID 创建后不可修改",
      displayName: "显示名称",
      displayNamePlaceholder: "例如：prod-main",
      syncMode: "接入模式",
      roleArn: "只读角色 ARN",
      roleArnHint:
        "必须是该账号内的 IAM 角色 ARN；平台同步与连通性校验都只使用该角色的只读权限。",
      syncEnabled: "启用同步",
    },
    action: {
      test: "测试连通",
    },
  },
};
