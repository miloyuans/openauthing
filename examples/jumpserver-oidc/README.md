# JumpServer OIDC Example

这个示例用于把 `JumpServer` 作为 `openauthing` 的 OIDC Client 接入，验证统一登录链路。

配置字段和参数命名参考 JumpServer 官方 OpenID 文档：

- [JumpServer OpenID 认证](https://docs.jumpserver.org/zh/master/admin-guide/authentication/openid/)

## 目录内容

- `docker-compose.yml`：启动 `openauthing + postgres + redis`
- `jumpserver-config.txt.example`：JumpServer `config.txt` 示例
- `seed/jumpserver_oidc_seed.sql`：JumpServer OIDC client / app / tenant 示例配置
- `seed/jumpserver_claims_seed.sql`：演示 `groups / roles` claim 的组和角色绑定
- `scripts/bootstrap.ps1`：一键启动 openauthing、跑 migration、seed client 和 demo user
- `tools/hash_argon2id.go`：运行时生成 Argon2id 哈希，避免明文 secret 入库

## 先决条件

- Docker Desktop
- PowerShell 7 或 Windows PowerShell
- 一个可配置 OpenID 的 JumpServer 实例

说明：

- 这个示例不在仓库里额外启动 JumpServer，本任务提供的是 openauthing 侧可复现联调环境 + JumpServer 侧配置模板
- 如果你的 JumpServer 版本或版本包没有 OpenID 配置项，先确认该版本是否支持 OpenID 登录

## 启动

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\jumpserver-oidc\scripts\bootstrap.ps1
```

脚本会完成：

1. 启动 `postgres / redis / openauthing`
2. 执行全部 migration
3. 创建 JumpServer 演示 tenant / app / OIDC client
4. 创建演示测试用户
5. 绑定演示 `groups / roles` claim

默认输出：

- openauthing: `http://localhost:8080`
- issuer: `http://host.docker.internal:8080`
- client_id: `jumpserver-local`
- client_secret: `jumpserver-local-secret`
- JumpServer callback: `http://localhost:8082/core/auth/openid/callback/`
- demo user: `jump.demo / Secret123!`
- demo groups: `jump_ops`
- demo roles: `jump_user`

如果你的 JumpServer 地址不是 `http://localhost:8082/`，可以覆盖：

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\jumpserver-oidc\scripts\bootstrap.ps1 `
  -JumpServerBaseURL "https://jump.example.test/"
```

## JumpServer 配置

示例配置文件见：

- [`jumpserver-config.txt.example`](./jumpserver-config.txt.example)

关键字段：

- `issuer`:
  `http://host.docker.internal:8080`
- `client_id`:
  `jumpserver-local`
- `client_secret`:
  `jumpserver-local-secret`
- `authorization endpoint`:
  `http://host.docker.internal:8080/oauth2/authorize`
- `token endpoint`:
  `http://host.docker.internal:8080/oauth2/token`
- `userinfo endpoint`:
  `http://host.docker.internal:8080/oauth2/userinfo`
- `jwks endpoint`:
  `http://host.docker.internal:8080/.well-known/jwks.json`
- `logout endpoint`:
  `http://host.docker.internal:8080/oauth2/logout`
- `scopes`:
  `openid profile email offline_access`
- `callback`:
  `${BASE_SITE_URL}core/auth/openid/callback/`

如果按默认本地联调值，JumpServer 里的关键配置可以写成：

- `BASE_SITE_URL=http://localhost:8082/`
- `AUTH_OPENID=True`
- `AUTH_OPENID_CLIENT_ID=jumpserver-local`
- `AUTH_OPENID_CLIENT_SECRET=jumpserver-local-secret`
- `AUTH_OPENID_PROVIDER_ENDPOINT=http://host.docker.internal:8080`
- `AUTH_OPENID_PROVIDER_AUTHORIZATION_ENDPOINT=http://host.docker.internal:8080/oauth2/authorize`
- `AUTH_OPENID_PROVIDER_TOKEN_ENDPOINT=http://host.docker.internal:8080/oauth2/token`
- `AUTH_OPENID_PROVIDER_JWKS_ENDPOINT=http://host.docker.internal:8080/.well-known/jwks.json`
- `AUTH_OPENID_PROVIDER_USERINFO_ENDPOINT=http://host.docker.internal:8080/oauth2/userinfo`
- `AUTH_OPENID_PROVIDER_END_SESSION_ENDPOINT=http://host.docker.internal:8080/oauth2/logout`
- `AUTH_OPENID_PROVIDER_SIGNATURE_ALG=RS256`
- `AUTH_OPENID_SCOPES=openid profile email offline_access`
- `AUTH_OPENID_ID_TOKEN_INCLUDE_CLAIMS=True`
- `AUTH_OPENID_USE_STATE=True`
- `AUTH_OPENID_USE_NONCE=True`
- `AUTH_OPENID_SHARE_SESSION=True`

## Claims 映射建议

推荐映射：

- `username`：`preferred_username`
- `email`：`email`
- `name`：`name`
- `groups`：`groups`
- 稳定唯一标识：`sub`

说明：

- 这个示例会把演示用户的 `groups` claim 设为 `jump_ops`
- 这个示例会把演示用户的 `roles` claim 设为 `jump_user`
- `userinfo` 当前会返回 `sub / preferred_username / email / name / groups / roles / sid`

组同步或角色映射建议：

- 如果你的 JumpServer 版本支持基于 `groups` 做组织或用户组映射，优先使用 `groups`
- `roles` 可以作为后续更细授权的参考 claim，但当前示例不假设 JumpServer 会自动消费 `roles`
- 对于生产环境，建议把 JumpServer 内部授权仍然控制在 JumpServer 侧，OIDC 先负责身份识别和基础用户属性同步

## 首次登录用户策略

推荐分两种模式：

1. 演示联调模式
   启用基于 claims 的首次登录自动创建或更新用户，让 `jump.demo` 第一次登录时能直接在 JumpServer 落地本地账号。
2. 严格生产模式
   只允许已有本地用户映射，不允许首次登录自动创建；这时请先在 JumpServer 预建与 `preferred_username` 或 `email` 对应的用户。

如果你的 JumpServer 版本支持基于 `AUTH_OPENID_ID_TOKEN_INCLUDE_CLAIMS` 或等价配置从 ID Token / userinfo 自动补齐用户信息，演示联调阶段建议开启。

## openauthing 侧演示配置

bootstrap 脚本会创建：

- tenant:
  `jumpserver-demo`
- app type:
  `oidc-client`
- app code:
  `jumpserver-local`
- client_id:
  `jumpserver-local`
- redirect_uri:
  `http://localhost:8082/core/auth/openid/callback/`
- post_logout_redirect_uri:
  `http://localhost:8082/core/auth/openid/logout/`
- grant_types:
  `authorization_code`, `refresh_token`
- scopes:
  `openid`, `profile`, `email`, `offline_access`
- token_endpoint_auth_method:
  `client_secret_basic`

演示测试用户：

- username:
  `jump.demo`
- email:
  `jump.demo@example.test`
- password:
  `Secret123!`

## 联调验证步骤

1. 运行 bootstrap
2. 在 JumpServer 配置 OpenID 参数，或把示例配置写入 `config.txt`
3. 重启 JumpServer 使 OIDC 配置生效
4. 访问 JumpServer 登录页，点击或进入 OpenID 登录流程
5. 浏览器应跳转到 `openauthing`
6. 用 `jump.demo / Secret123!` 登录
7. 登录成功后应跳回 JumpServer
8. 在 JumpServer 中确认用户名、邮箱、显示名映射正确
9. 如果 JumpServer 消费了 `groups` claim，确认演示用户能看到 `jump_ops`

## Session 与 Logout 当前边界

- `openauthing` 当前支持中心 session、`/oauth2/logout`、浏览器 cookie 清理和 `post_logout_redirect_uri` 校验
- 当前还没有实现针对 JumpServer 的 front-channel / back-channel 单点登出编排
- `AUTH_OPENID_SHARE_SESSION=True` 可以帮助 JumpServer 侧复用会话语义，但不能替代完整协议级单点登出

## 常见问题

### issuer 不匹配

现象：

- JumpServer 保存配置时报 OIDC provider 错误
- 或登录后回调失败

排查：

- 确认 `issuer` 和各 endpoint 都是 `http://host.docker.internal:8080`
- 确认 discovery 页面是：
  `http://host.docker.internal:8080/.well-known/openid-configuration`
- 如果宿主机浏览器无法解析 `host.docker.internal`，在本机 hosts 中加：
  `127.0.0.1 host.docker.internal`

### callback 不匹配

现象：

- openauthing 返回 `invalid_request`
- 日志里提示 `redirect_uri is invalid`

排查：

- `redirect_uri` 必须与 openauthing seed 中的值完全一致
- 默认值是：
  `http://localhost:8082/core/auth/openid/callback/`
- `BASE_SITE_URL` 末尾必须保留 `/`

### scopes 不足

现象：

- JumpServer 登录后拿不到邮箱或显示名

排查：

- 至少使用 `openid profile email`
- 如需 refresh token，再保留 `offline_access`

### RS256 / JWKS 校验失败

现象：

- JumpServer 报 ID Token 签名错误

排查：

- `AUTH_OPENID_PROVIDER_SIGNATURE_ALG` 用 `RS256`
- `AUTH_OPENID_PROVIDER_JWKS_ENDPOINT` 指向 `/.well-known/jwks.json`
- 如果你没有为 openauthing 配置固定签名私钥，重启后 `kid` 会变化；联调中如遇缓存问题，刷新 JumpServer 配置并重新登录

### 首次登录后没有本地用户

排查：

- 先确认 JumpServer 版本是否支持基于 OIDC claims 自动创建或更新用户
- 如果不支持自动创建，请先在 JumpServer 里手工创建与 `preferred_username` 或 `email` 对应的本地用户

### 登出后没有形成完整双向退出

排查：

- 当前 openauthing 只能保证自己的中心 session 和 token 被销毁
- 如果你要验证主登录链路，可以先以“登录成功并回跳 JumpServer”为主，不把完整单点登出作为当前任务验收前提
