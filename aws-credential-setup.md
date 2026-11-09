# AWS 凭证与账号接入

> 适用场景：第一次把平台接到真实 AWS 账号，或者换了一台机器部署。
> 这一页要解决的问题只有一个：**平台用哪个身份去读 AWS，以及这个身份从哪来。**
> 配错这一层，界面上「添加账号」那一步一定失败，且报错往往看不懂。

## 1. 两层身份，不要混

| 层 | 谁在用 | 干什么 | 生命周期 |
|---|---|---|---|
| **入口身份**（entry） | 平台进程自己 | 调 `sts:AssumeRole`，换成被管账号的只读角色 | 长期凭据或计算角色，由部署方式决定 |
| **采集身份**（collector） | 被扮演的只读角色 | 真正调 `iam:List*` / `iam:Get*` 采集 | 临时凭据，默认 1 小时 |

平台永远是只读的：采集身份只挂 AWS 托管策略 `IAMReadOnlyAccess`，入口身份只需要
`sts:AssumeRole`，两者都不需要任何写权限。

**为什么非要有入口身份？** 角色不能自己扮演自己——总要有一个已被 AWS 认可的身份
发起第一次 `sts:AssumeRole`。这个「信任锚」藏不掉，能选的只有它的形态：长期 AK、
计算角色（实例角色 / IRSA），或证书换来的临时凭据。

## 2. 平台从哪儿取入口凭证

走 AWS SDK v2 的**默认凭据链**，顺序是：

1. 环境变量 `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` / `AWS_SESSION_TOKEN`
2. 共享配置里的 profile（`~/.aws/credentials`、`~/.aws/config`），可用
   `AWS_PROFILE` 指定用哪个；profile 里可以配 `credential_process`
3. 容器 / 实例元数据（ECS task role、EC2 instance profile、EKS Pod Identity）
4. SSO 缓存（`aws sso login` 之后）

代码里 `AWS_PROFILE` 为空时就是「按上面顺序自己找」；设了值则**只用该 profile**
（`config.WithSharedConfigProfile`）。

所以**本地不是必须有 aws profile**——但必须存在上面四种来源之一。生产上推荐让
profile 指向 `credential_process`（第 4 节 B 路），这样配置文件里没有密钥。

> **容器部署注意**：API 和 sync-worker 跑在容器里，`docker-compose.yml` 把宿主机的
> `~/.aws` **只读挂载**到容器内的 `/root/.aws`。所以 profile 一律定义在**宿主机**上
> （`/root/.aws/config`、`/root/.aws/credentials`），不要试图在容器里建——容器重建
> 就没了。如果改用 `AWS_CONFIG_FILE` 指向别处，记得同步调整挂载路径。

启动日志会打印实际使用的来源，`API` 和 `sync-worker` 各一行：

```
level=INFO msg="aws entry credential" profile=<名字或空> region=<region> external_id_set=<true|false>
```

## 3. 场景一：平台跑在 AWS 上（EC2 / EKS）

这种部署**不需要任何长期密钥**，`.env` 里不要填 `AWS_ACCESS_KEY_ID`。

### 3.1 EC2：实例角色

这里有两个角色，别混：**实例角色**（`iam-hub-entry`，由 EC2 服务扮演）和**采集角色**
（`<collector-role>`，由实例角色扮演）。两份信任策略各认一个主体。

1. 实例角色的信任策略——`ec2.amazonaws.com` 只该出现在这里：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowEC2Assume",
    "Effect": "Allow",
    "Principal": { "Service": "ec2.amazonaws.com" },
    "Action": "sts:AssumeRole"
  }]
}
```

⚠️ 这段**不能**写给采集角色。`ec2.amazonaws.com` 是服务主体，不带实例归属：任何账号
的 EC2 实例只要知道采集角色 ARN，就能把它扮演走，等于把只读权限开放给全网 EC2。采集
角色必须用实例角色的**角色 ARN** 做 Principal，ARN 自带账号与角色名，天然收窄。

2. 实例角色的权限策略，只需要一条：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::<账号ID>:role/<collector-role>"
  }]
}
```

3. 采集角色的信任策略认实例角色：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowEntryRoleAssume",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<账号ID>:role/iam-hub-entry" },
    "Action": "sts:AssumeRole"
  }]
}
```

4. 确认容器/进程能访问元数据（`169.254.169.254`）。如果实例开了
   `HttpTokens=required`（IMDSv2，默认推荐），SDK 会自动走 v2，不用配置；但
   **Docker 里要允许出站到该地址**，否则报 `failed to refresh cached credentials`。
5. `.env` 里只留 `AWS_REGION`，`AWS_PROFILE` 留空。

单账号可以省掉一级：实例角色直接挂 `IAMReadOnlyAccess`，平台选
`CURRENT_CREDENTIALS`，此时只有实例角色一个角色，上面第 1 步那份信任策略就是全部。

⚠️ **角色链的会话上限是 1 小时**：用临时凭证（实例角色）再扮演下一个角色属于 role
chaining，AWS 固定限制 1 小时，把采集角色的 `MaxSessionDuration` 调到 12 小时**也不
生效**。当前单次同步是分钟级，够用；哪天账号多到逼近 1 小时，出路是去掉链式——单账号
用 `CURRENT_CREDENTIALS`，多账号用 Roles Anywhere 直接给出采集角色凭据。

### 3.2 EKS：IRSA（推荐）

1. 建一个 IAM 角色，信任集群的 OIDC provider，并限定命名空间/ServiceAccount：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Principal": {
      "Federated": "arn:aws:iam::<账号ID>:oidc-provider/oidc.eks.<region>.amazonaws.com/id/<OIDC_ID>"
    },
    "Action": "sts:AssumeRoleWithWebIdentity",
    "Condition": {
      "StringEquals": {
        "oidc.eks.<region>.amazonaws.com/id/<OIDC_ID>:sub":
          "system:serviceaccount:<namespace>:<serviceaccount>"
      }
    }
  }]
}
```

2. 这个角色同样只给它 `sts:AssumeRole`（指向采集角色），然后建一个信任它的采集角色
   （`Principal` 填上面这个角色 ARN，和 3.1 第 2 步一样）。
3. Deployment 的 ServiceAccount 加注解：

```yaml
metadata:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::<账号ID>:role/iam-hub-entry
```

4. SDK 会自动读到注入的 `AWS_ROLE_ARN` + `AWS_WEB_IDENTITY_TOKEN_FILE`，
   平台侧**零配置**。

> 单账号且只读的情况下可以更省一步：直接把 `IAMReadOnlyAccess` 挂在入口角色上、
> 账号配置选 `CURRENT_CREDENTIALS`，不必再套一层角色。多账号仍然建议分开——入口
> 角色只负责「能扮演」，读权限全在各自的采集角色里。

## 4. 场景二：平台跑在任意地方（on-prem VM / 笔记本 / 自建 K8s）

没有实例角色可用，只能自己提供入口凭证。三条路，**A 是推荐方案**：先用它把链路跑
通并投入生产，B 作为后续的零密钥加固，C 取决于能否接受换宿主机。

| 路径 | 长期 AK | 需要 profile？ | 定位 |
|---|---|---|---|
| A. 静态 AK（环境变量或 profile） | 有 | 否（但更常见） | **on-prem 部署的推荐方案** |
| B. `credential_process`（Roles Anywhere / aws-vault / SSO） | **无** | 是 | 后续加固选项（零 AK） |
| C. 把平台搬到 EC2/ECS | **无** | 否 | 有 AWS 环境且可换宿主机时 |

### A. 静态 AK（推荐方案）

```bash
# .env（不要提交，也不要放进镜像）
AWS_ACCESS_KEY_ID=AKIA...
AWS_SECRET_ACCESS_KEY=...
AWS_REGION=us-east-1
```

这个用户的权限应当**只有** `sts:AssumeRole` 指向采集角色：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": "arn:aws:iam::<账号ID>:role/<collector-role>"
  }]
}
```

⚠️ 常见错误：给入口用户直接挂 `IAMReadOnlyAccess`。这时它能直接读 IAM，采集角色
完全没用上——等于「用用户密钥采集」，角色成了摆设。要么摘掉读权限，要么承认自己在
用用户身份。

同账号下 `Principal` 也可以写 `arn:aws:iam::<账号ID>:root`，语义是「账号内任何
持有 `sts:AssumeRole` 权限的身份」，比写具体用户宽。真要这么写，补一条
`"Condition": {"ArnLike": {"aws:PrincipalArn": "arn:aws:iam::<账号ID>:user/<entry-user>"}}`
把它钉回来。

为什么把它定为 on-prem 的推荐方案：`Roles Anywhere` 一类零密钥方案要维护 CA、证书
续期和 trust anchor，设施成本半天起步；而静态 AK 方案里这把 AK 的权限被收敛到只剩
`sts:AssumeRole`、Resource 钉死采集角色——泄露的最坏后果是「有人变成了只读角色」，
拿不到任何写能力和账号外的资源。用最小残余风险换零设施成本，对内网部署是笔划算的
账。把 AK 的管理当普通运维纪律执行即可：不进 git、不进镜像、定期轮换、独立用户。

### B. `credential_process`（零长期密钥的后续加固选项）

平台不改代码，只要 profile 指向一个会打印 `AccessKeyId / SecretAccessKey /
SessionToken / Expiration` 的命令。最标准的是 **IAM Roles Anywhere**：

1. 建 trust anchor（挂你的 CA 证书）+ profile（绑定采集角色 ARN）；
2. 采集角色的信任策略改成信任服务主体，并用 trust anchor 收紧：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowRolesAnywhere",
    "Effect": "Allow",
    "Principal": { "Service": "rolesanywhere.amazonaws.com" },
    "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
    "Condition": {
      "StringEquals": { "aws:SourceAccount": "<账号ID>" },
      "ArnEquals": {
        "aws:SourceArn": "arn:aws:rolesanywhere:<region>:<账号ID>:trust-anchor/<TA_ID>"
      }
    }
  }]
}
```

3. VM 上装 `aws_signing_helper`，`~/.aws/config` 写：

```ini
[profile iam-hub]
credential_process = aws_signing_helper credential-process \
  --certificate /etc/iam-hub/cert.pem \
  --private-key /etc/iam-hub/key.pem \
  --trust-anchor-arn arn:aws:rolesanywhere:<region>:<账号ID>:trust-anchor/<TA_ID> \
  --profile-arn arn:aws:rolesanywhere:<region>:<账号ID>:profile/<PROFILE_ID> \
  --role-arn arn:aws:iam::<账号ID>:role/<collector-role>
```

4. `.env` 设 `AWS_PROFILE=iam-hub`，不要填 AK。

这条路的注意点：Roles Anywhere 给出的**已经是采集角色的凭据**，单账号场景直接选
`CURRENT_CREDENTIALS` 即可，不必再 `AssumeRole` 一次。

### C. 平台搬到 EC2

见 3.1，最省心，前提是能接受换宿主机。

### D. A 和 B 共用一个采集角色（迁移期）

A、B 两种入口要的是**同一个**角色：权限策略都是 `IAMReadOnlyAccess`，差别只在信任
策略里「谁可以扮演它」。信任策略可以有**多条 Statement**，所以迁移期让一个角色同时
接受两种入口即可，不用建两个角色：

```json
{
  "Version": "2012-10-17",
  "Statement": [
    {
      "Sid": "AllowEntryUserAssumeRole",
      "Effect": "Allow",
      "Principal": { "AWS": "arn:aws:iam::<账号ID>:user/<entry-user>" },
      "Action": "sts:AssumeRole"
    },
    {
      "Sid": "AllowRolesAnywhere",
      "Effect": "Allow",
      "Principal": { "Service": "rolesanywhere.amazonaws.com" },
      "Action": ["sts:AssumeRole", "sts:TagSession", "sts:SetSourceIdentity"],
      "Condition": {
        "StringEquals": { "aws:SourceAccount": "<账号ID>" },
        "ArnEquals": {
          "aws:SourceArn": "arn:aws:rolesanywhere:<region>:<账号ID>:trust-anchor/<TA_ID>"
        }
      }
    }
  ]
}
```

三条纪律：

1. **一个 Statement 只放一类主体。** `{"AWS": [...], "Service": "..."}` 混写在一条里
   是「或」关系，但读的人几乎都会当成「且」，排错时尤其致命。
2. **迁移完成后删掉不再用的那条。** 留着等于给旧入口永久保留一条扮演路径，
   「最小权限」在这里是随时间衰减的。
3. **`AWS_EXTERNAL_ID` 是全局单值。** 设了它，凡是要走 `AssumeRole` 的 Statement 都得
   带同一个 `sts:ExternalId` 条件，否则那条路径直接 `AccessDenied`。

## 5. 在平台里添加账号

「账号管理 → 添加账号」只有四个字段要填，但选错 `sync_mode` 是第一步最常见的坑。

| 字段 | 说明 |
|---|---|
| AWS 账号 ID | 12 位数字，被采集的账号（不是平台运行所在地） |
| 显示名 | 任意 |
| 只读角色 ARN | `ASSUME_ROLE` 模式必填；`CURRENT_CREDENTIALS` 模式忽略 |
| 同步模式 | 见下表 |

| sync_mode | 含义 | 前提 | 适用 |
|---|---|---|---|
| `ASSUME_ROLE` | 用入口身份扮演「只读角色 ARN」 | 角色的信任策略含入口身份；入口身份有 `sts:AssumeRole` | **生产、多账号** |
| `CURRENT_CREDENTIALS` | 直接用入口身份采集，不扮演 | 入口身份本身就有 `IAMReadOnlyAccess` | 单账号调试、Roles Anywhere 直连 |

保存时平台会做一次连通性校验：按所选模式取凭证（`ASSUME_ROLE` 用 900 秒会话），
然后调 `sts:GetCallerIdentity`。失败会原样返回原因，常见值见第 7 节。

### 5.1 两个账号的最小配置（跨账号信任）

入口身份只需要**一个**，每个被管账号各放一个采集角色，一共三份 JSON。入口是 EC2/EKS
实例角色还是 on-prem 的 IAM 用户（静态 AK）不影响这套结构——区别只在「入口角色的
ARN」换成「入口用户的 ARN」，三份 JSON 照用。

**入口角色的权限策略**（在平台所在账号 A，Resource 列出两个采集角色）：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Effect": "Allow",
    "Action": "sts:AssumeRole",
    "Resource": [
      "arn:aws:iam::<账号A>:role/iam-governance-collector",
      "arn:aws:iam::<账号B>:role/iam-governance-collector"
    ]
  }]
}
```

**账号 A 的采集角色**信任入口角色（同账号，写完整 ARN）：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowEntryRoleAssume",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<账号A>:role/iam-hub-entry" },
    "Action": "sts:AssumeRole"
  }]
}
```

**账号 B 的采集角色**信任 A 账号的入口角色——跨账号同样直接写完整 ARN，不必写
账号 root：

```json
{
  "Version": "2012-10-17",
  "Statement": [{
    "Sid": "AllowHubEntryAssume",
    "Effect": "Allow",
    "Principal": { "AWS": "arn:aws:iam::<账号A>:role/iam-hub-entry" },
    "Action": "sts:AssumeRole"
  }]
}
```

要点：

- **跨账号是两侧都要点头**：A 侧入口角色的身份策略允许它扮演 B 的采集角色，B 侧
  采集角色的信任策略允许 A 的入口身份。B 侧不需要给任何身份加权限策略，也不要在
  B 侧重复建入口角色。
- 两个账号用**同一个角色名**可以让 ARN 只差账号 ID。将来加新账号，把入口角色的
  Resource 换成通配 `arn:aws:iam::*:role/iam-governance-collector` 即可——信任策略
  仍在对端管住谁能扮演，这不是放权。
- 平台侧就是「添加账号」两行：各选 `ASSUME_ROLE`，只读角色 ARN 分别填 A、B 的采集
  角色。采集只读与 CI 的 apply 是两套身份，后者在 Terraform 仓库的 workflow 里另配。
- 这些都是自己组织内的账号，**不要设 `AWS_EXTERNAL_ID`**；它只在被管账号属于第三方
  （你方不是对方账号的 IAM 管理员）时才有意义，且是全局单值，见 4.D 第 3 条。

验证：在入口身份下对两个 ARN 各跑一次
`aws sts assume-role --role-arn <采集角色ARN> --role-session-name probe`，
都能返回临时凭证即通。

## 6. 最小权限对照

| 身份 | 需要的权限 | 不需要 |
|---|---|---|
| 入口用户 / 入口角色 | `sts:AssumeRole` → 采集角色 ARN | 任何 `iam:*`、任何写操作 |
| 采集角色 | AWS 托管 `IAMReadOnlyAccess` | 写权限、`iam:Create*` 等 |
| 组织模式（多账号） | 入口身份额外 `organizations:ListAccounts` | `organizations:*` 其余 |

角色会话默认 1 小时（平台未指定 `DurationSeconds`）。单次同步在千次请求量级只要
几分钟，够用。注意：经由入口身份扮演采集角色属于 role chaining，AWS 固定上限 1 小时，
调采集角色的 `MaxSessionDuration` 不能突破它；账号规模真逼近上限时，出路是去掉链式
（Roles Anywhere 直接给出采集角色凭据，或单账号 `CURRENT_CREDENTIALS`）。

## 7. 排错对照

| 报错 | 原因 | 处理 |
|---|---|---|
| `Principal cannot be empty!` | 信任策略里 `"Principal": {}` 没填 | 填具体 ARN 或服务主体，见第 3 节 |
| `AccessDenied ... sts:AssumeRole` | 信任策略没包含入口身份，或入口身份缺 `sts:AssumeRole` | 两侧都要改，缺一不可 |
| `AccessDenied`（采集时 `iam:List*`） | 采集角色没挂 `IAMReadOnlyAccess` | 挂上托管策略 |
| `failed to refresh cached credentials` | 找不到任何入口凭证 | 配 AK / profile / 实例角色；看启动日志那行 |
| `InvalidClientTokenId` | AK 失效或被禁用 | 换密钥 |
| `An error occurred (AccessDenied) when calling AssumeRole ... ExternalId` | 设了 `AWS_EXTERNAL_ID` 但信任策略没写 `sts:ExternalId` 条件 | 两边保持一致 |
| 采集只在部分账号失败 | 某账号角色信任策略/ARN 写错 | 逐个用第 5 节的连通性校验排 |

## 8. 当前限制

- `AWS_EXTERNAL_ID` 是**全局单一值**，不能按账号区分；多账号各自不同 ExternalId
  的场景暂不支持。
- 一个进程只用一个入口身份。同时管多个云/多个根账号，需要部署多套实例。
