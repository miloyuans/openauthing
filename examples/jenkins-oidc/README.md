# Jenkins OIDC Example

这个示例用于把 `openauthing` 作为 OIDC Provider，接到本地 Jenkins。

## 目录内容

- `docker-compose.yml`：启动 `openauthing + Jenkins + postgres + redis`
- `jenkins/Dockerfile`：预装 Jenkins OIDC 插件
- `jenkins/plugins.txt`：当前示例安装的 Jenkins 插件列表
- `seed/jenkins_oidc_seed.sql`：Jenkins OIDC client / app / tenant 示例配置
- `scripts/bootstrap.ps1`：一键启动、跑 migration、seed demo client 和 demo user
- `tools/hash_argon2id.go`：运行时生成 Argon2id 哈希，避免明文 secret 入库

## 先决条件

- Docker Desktop
- PowerShell 7 或 Windows PowerShell

## 启动

在仓库根目录执行：

```powershell
powershell -ExecutionPolicy Bypass -File .\examples\jenkins-oidc\scripts\bootstrap.ps1
```

脚本会完成：

1. 启动 `postgres / redis / openauthing / jenkins`
2. 执行全部 migration
3. 创建 Jenkins 演示 tenant / app / OIDC client
4. 创建演示测试用户

默认输出：

- openauthing: `http://localhost:8080`
- Jenkins: `http://localhost:8081`
- OIDC issuer: `http://host.docker.internal:8080`
- Jenkins client_id: `jenkins-local`
- Jenkins client_secret: `jenkins-local-secret`
- demo user: `jenkins.demo / Secret123!`

## Jenkins 侧插件

示例镜像会预装官方 Jenkins 插件：

- `oic-auth`

插件来源：

- Jenkins OpenID Connect Authentication 插件官方页：<https://plugins.jenkins.io/oic-auth>

## Jenkins 接入步骤

1. 打开 `http://localhost:8081`
2. 进入 `Manage Jenkins` -> `Security`
3. 在 `Security Realm` 里选择 `OpenID Connect`
4. 配置以下值

推荐配置：

- `Well-known OpenID Configuration URL`:
  `http://host.docker.internal:8080/.well-known/openid-configuration`
- `Client ID`:
  `jenkins-local`
- `Client Secret`:
  `jenkins-local-secret`
- `Scopes`:
  `openid profile email`
- `User name field`:
  `preferred_username`
- `Full name field`:
  `name`
- `Email field name`:
  `email`
- `Groups field name`:
  `groups`

回调地址：

- 登录回调：`http://localhost:8081/securityRealm/finishLogin`
- 登出回调：`http://localhost:8081/OicLogout`

用户标识映射建议：

- 唯一用户标识：`sub`
- Jenkins 显示用户名：`preferred_username`
- 邮箱映射：`email`
- 展示名称：`name`
- 组映射：`groups`

说明：

- Jenkins 官方插件文档给出的通用 quickstart 提到了 `scope: openid profile email`、登录回调 `${JENKINS_ROOT_URL}/securityRealm/finishLogin` 和登出回调 `${JENKINS_ROOT_URL}/OicLogout`
- `openauthing` 当前主链路只支持 `response_type=code`，所以这个示例按 Authorization Code 配置，不启用隐式流

## openauthing 侧演示配置

bootstrap 脚本会创建：

- tenant:
  `jenkins-demo`
- app type:
  `oidc-client`
- app code:
  `jenkins-local`
- client_id:
  `jenkins-local`
- redirect_uri:
  `http://localhost:8081/securityRealm/finishLogin`
- post_logout_redirect_uri:
  `http://localhost:8081/OicLogout`
- grant_types:
  `authorization_code`, `refresh_token`
- scopes:
  `openid`, `profile`, `email`, `offline_access`
- token_endpoint_auth_method:
  `client_secret_basic`

演示测试用户：

- username:
  `jenkins.demo`
- email:
  `jenkins.demo@example.test`
- password:
  `Secret123!`

## 联调验证步骤

1. 跑完 bootstrap
2. 在 Jenkins `Security Realm` 中填好上面的 OIDC 配置并保存
3. 退出当前 Jenkins 页面
4. 访问 Jenkins 首页
5. Jenkins 应跳转到 `openauthing`
6. 用 `jenkins.demo / Secret123!` 登录
7. 登录成功后应回跳 Jenkins，并能看到 Jenkins 用户名和邮箱

## 常见问题

### issuer 不匹配

现象：

- Jenkins 保存配置时报 issuer 错误
- 或跳转后回调失败

排查：

- 确认 Jenkins 配置的 well-known URL 是
  `http://host.docker.internal:8080/.well-known/openid-configuration`
- 确认 discovery 里的 `issuer` 也是 `http://host.docker.internal:8080`
- 如果宿主机浏览器无法解析 `host.docker.internal`，在本机 hosts 中加：
  `127.0.0.1 host.docker.internal`

### redirect_uri 不匹配

现象：

- openauthing 返回 `invalid_request`
- 日志里提示 `redirect_uri is invalid`

排查：

- Jenkins 回调必须是 `http://localhost:8081/securityRealm/finishLogin`
- openauthing seed 的 redirect_uri 也必须一致
- 注意端口不能写成 `8080`

### scope 不足

现象：

- Jenkins 登录后拿不到邮箱或组

排查：

- Jenkins scopes 至少填 `openid profile email`
- 如果后续需要 refresh token，再确认客户端允许 `offline_access`

### Jenkins 识别不到用户名或邮箱

排查：

- `User name field` 用 `preferred_username`
- `Email field name` 用 `email`
- `Full name field` 用 `name`
- `Groups field name` 用 `groups`
- `openauthing` 当前的 `userinfo` 已返回 `sub / preferred_username / email / name / groups / roles / sid`

### 登录成功但退出不回跳

排查：

- 先确认 Jenkins 侧保存了 `http://localhost:8081/OicLogout`
- 再确认 openauthing client 配置里的 `post_logout_redirect_uri` 也是这个值
- 如需先跑通登录链路，可以先只验证登录，不强依赖 RP 发起登出
