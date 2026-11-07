export default {
  login: {

    success: "已登录：{{user}}",
    failed: "登录失败",
    configError: "无法读取认证配置",
    devMode: "开发模式",
    devModeHint:
      "仅允许 loopback 访问；任何 X-User-ID 都会获得 platform_admin。不要在生产环境使用。",
    devUserId: "开发用户 ID",
    devUserIdRequired: "请输入开发用户 ID",
    enterDev: "进入开发环境",
    tokenLabel: "Platform token",
    tokenRequired: "请输入平台 token",
    signIn: "登录",
    tokenHint: "token 仅保存在当前浏览器会话（sessionStorage），关闭标签页后失效。",
    unknownMode: "认证模式未知",
    unknownModeHint: "后端未返回有效的 AUTH_MODE，请检查服务配置。",
  },
};
