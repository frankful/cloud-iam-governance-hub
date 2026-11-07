export default {
  users: {

    title: "用户与令牌",
    action: {
      createUser: "新建用户",
      tokens: "令牌",
      issueToken: "签发",
      revokeToken: "吊销",
      provision: "开通到云",
    },
    column: {
      userId: "用户 ID",
      displayName: "姓名",
      roles: "角色",
    },
    hint: {
      title: "这里管理的是平台身份（登录平台的人），不是 AWS IAM 主体。",
      body: "令牌明文只在签发时显示一次，请通过带外渠道交给本人；只保存在浏览器会话中，关掉标签页即失效。",
    },
    modal: {
      createTitle: "新建用户",
      editTitle: "编辑用户 {{id}}",
      tokenTitle: "令牌 · {{id}}",
      tokenTitleGeneric: "令牌",
    },
    form: {
      userId: "用户 ID",
      userIdRequired: "请填写用户 ID",
      userIdHint: "平台/SSO 主体标识，创建后不可修改",
      displayName: "姓名",
      displayNameRequired: "请填写姓名",
      roleRequired: "至少选择一个角色",
      roleHint: "角色按「设置」语义替换：本次未勾选的角色会被移除",
      approverAccounts: "可审批的账号",
      approverAccountsHint:
        "勾选该用户可审批的 AWS 账号；与「同步管理 → 账号配置 → 审批人」写的是同一份绑定，两边互相可见。",
      approverAccountsPlaceholder: "选择该用户可审批的账号",
    },
    token: {
      defaultName: "admin console",
      issueTitle: "签发新令牌",
      nameRequired: "请填写令牌名称",
      expiryHours: "有效期（小时）",
      secretTitle: "令牌明文（只显示这一次）",
      secretHint: "关闭本窗口后无法再次查看；请立即复制并通过带外渠道交给本人。",
      revoked: "已吊销",
      active: "有效",
      column: {
        prefix: "前缀",
        expires: "到期",
        lastUsed: "最近使用",
      },
    },
    toast: {
      created: "用户已创建",
      updated: "用户已更新",
      tokenIssued: "令牌已签发：明文只显示这一次",
      tokenRevoked: "令牌已吊销",
    },
    approverWarn: {
      title: "该用户仍是 {{count}} 个账号的审批人",
      content:
        "停用或取消审批角色后，账号 {{accounts}} 的审批链将缺少此人：AUTO 建单可能因剩余审批人为空而失败，在途工单可能无人可审。请先给这些账号补上其他审批人——可在其他用户的「可审批的账号」里勾选，或到「同步管理 → 账号审批人」调整。",
      confirm: "仍要继续",
    },
    provision: {
      title: "开通到云 · {{id}}",
      hint: "每个选中的云账号生成一张「创建用户」工单（IAM 用户名 = 平台用户 ID），走正常审批 → PR → apply 流程；平台不管理云上访问密钥。",
      accounts: "目标云账号",
      accountsRequired: "请选择至少一个云账号",
      disabledFiltered:
        "已过滤 {{count}} 个不可用账号（未接入平台配置或已停用同步）；如需开通，请先在「同步管理 → 账号」中启用。",
      groups: "初始加入组（可选）",
      groupsHint:
        "只列出所有选中账号都存在的组；留空则不加入任何组，之后可用组成员变更工单调整。",
      groupsPlaceholder: "选择用户创建后加入的组",
      groupsPlaceholderNoAccount: "请先选择云账号",
      groupsLoadFailed: "组列表加载失败，请重试",
      approvalMode: "审批模式",
      modeAuto: "AUTO · 按账号绑定自动圈定审批人",
      modeManual: "MANUAL · 手动指定审批人",
      approvers: "审批人",
      approversRequired: "MANUAL 模式必须指定审批人",
      submit: "生成工单",
      resultsTitle: "已按账号生成工单",
      resultsHint: "失败的账号未生成工单，可根据错误修正后重试该账号。",
      conflictTag: "已存在冲突",
      conflictHint:
        "同名 IAM 用户已存在时不会重复创建（也不会自动导入）：若尚未纳管，请用「新建工单 → 创建 IAM 用户」勾选「导入已存在资源」完成纳管；已纳管则走对应的更新工单。",
      colAccount: "云账号",
      colTicket: "工单号",
      created: "已创建",
      toastAll: "全部工单创建成功",
      toastPartial: "{{failed}} 个账号创建失败，详见列表",
    },
  },
};
