# 平台首次使用：管理员登录引导

> 适用场景：全新部署后没有任何可用 token，管理台接口全部要求已认证身份——
> 「鸡生蛋」问题有两条解决路径：默认的**启动自举**（无需手工操作），
> 以及手工的 CLI 兜底。日常签发/吊销见「日常流程」。

## 方式一（默认）：启动自举

`AUTH_MODE=api-token` 启动时，若**没有任何 active 的 platform_admin 用户**，
api 会自动：

1. 创建（或激活）默认管理员 `admin`（显示名「平台管理员」）并授予
   `platform_admin`（已有角色不会被覆盖）；
2. 签发一枚 bootstrap token（默认 **120 天**），明文写入工作目录下的
   `bootstrap-admin-token.txt`（`0600`）；
3. 日志里只记录文件路径 + token 前缀（`iamg_xxxxxxxx`），**不打印明文**；
4. 之后的每次启动都是有管理员的 no-op——**重启绝不重发新 token**。

打开 `bootstrap-admin-token.txt`，把里面的 token 粘贴进登录页即可。首次登录
后请尽快吊销这枚 token（设置 → Token 管理）并删除该文件（已加入 `.gitignore`）。

环境变量（均可选）：

| 变量 | 默认 | 说明 |
|---|---|---|
| `BOOTSTRAP_ADMIN_USER_ID` | `admin` | 默认管理员用户 ID |
| `BOOTSTRAP_ADMIN_TOKEN_TTL` | `2880h`（120 天） | Go duration |
| `BOOTSTRAP_ADMIN_TOKEN_FILE` | `bootstrap-admin-token.txt` | 置空则不落文件，secret 只在启动结果里 |

适用边界：admin 存在但 token 全部丢失/过期时**不会**触发自举（有管理员就不动），
改走下面的 CLI。

## 方式二（CLI 兜底）：手工签发

前提：`platform_user` 里已有管理员账号（种子数据或手工 INSERT，
如 `admin` / `example-org`）。

```bash
# 1. 直连数据库给首个管理员签发 token；用户还没有任何角色时
#    --bootstrap-admin 会顺带授予 platform_admin
go run ./cmd/platform-token -user-id example-org -name "first admin token" \
  -expires-in 48h -bootstrap-admin

# 2. 输出中的 token（iamg_ 前缀，仅此一次显示）粘贴进登录页即可
```

行为细节：

- `-user-id` 必须是 `platform_user` 中 `is_active=TRUE` 的用户，否则报
  `platform user is missing or inactive`；
- 用户存在但**没有任何平台角色**：不带 `-bootstrap-admin` 直接报错并提示；
  带上则授予 `platform_admin`（幂等，已有角色不重复授）后正常签发；
- secret 只存 SHA-256 摘要，明文丢失只能吊销重发。

## 日常流程（已有管理员登录后）

| 操作 | 入口 | 权限 |
|---|---|---|
| 给任意用户签发 token | `POST /api/v1/platform/users/:userID/tokens` | platform_admin |
| 用户/角色管理 | `PUT /api/v1/platform/users/:userID` | platform_admin |
| 查看 token 列表 | `GET /api/v1/platform/tokens`（无 secret） | platform_admin |
| 吊销 token | `POST /api/v1/platform/tokens/:tokenID/revoke` | 本人任意角色；admin 可吊他人 |

签发侧守卫（2026-10-30 起）：目标用户**无任何平台角色**时签发直接
400（`has no platform role; assign at least one role ...`）——此前会签发
成功但登录必然 401 且无解释。角色分配见 `PUT /platform/users/:userID`
的 `roles` 字段（覆盖式更新）。

## 认证模式（AUTH_MODE）

- `development`：请求头 `X-User-ID` 伪登录，仅本地开发；
- `api-token`：Bearer token（登录页粘贴 token）。生产/演示用这个。

## 下一步：接一个真实 AWS 账号

登录进去之后紧接着就是「添加账号」，而这一步失败绝大多数不是平台的问题，是
入口凭证没配好（找不到凭证、信任策略没包含入口身份、角色没挂
`IAMReadOnlyAccess`）。四种部署形态分别怎么配、报错怎么读，见
[aws-credential-setup.md](aws-credential-setup.md)。
