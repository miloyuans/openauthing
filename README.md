# openauthing

`openauthing` 是一个自建统一认证平台。当前仓库已经具备：

- 基础配置、日志、统一错误返回和中间件
- 基础健康检查与 `ping` 接口
- 第一版核心数据库表
- `users / groups / roles / applications` 的 repo / service / handler 基础 CRUD

本任务仍然不实现后台鉴权，只提供后续业务继续扩展所需的最小可用管理 API。

## 目录结构

```text
cmd/server
internal/auth
internal/apps
internal/config
internal/logging
internal/platform
internal/server
internal/shared
internal/store
internal/usercenter
migrations
scripts
web/admin
deploy/docker
docs
```

## 配置

配置优先级：

1. 环境变量
2. `OPENAUTHING_CONFIG_FILE` 指定的本地 JSON 配置文件
3. 代码默认值

当前支持：

| 配置项 | 环境变量 | 示例值 |
| --- | --- | --- |
| app name | `OPENAUTHING_APP_NAME` | `openauthing` |
| app env | `OPENAUTHING_ENV` | `development` |
| http listen addr | `OPENAUTHING_HTTP_ADDR` | `:8080` |
| cors origins | `OPENAUTHING_HTTP_ALLOWED_ORIGINS` | `http://localhost:5173` |
| postgres dsn | `OPENAUTHING_POSTGRES_DSN` | `postgres://openauthing@localhost:5432/openauthing?sslmode=disable` |
| redis addr | `OPENAUTHING_REDIS_ADDR` | `localhost:6379` |
| log level | `OPENAUTHING_LOG_LEVEL` | `info` |
| session secret | `OPENAUTHING_SESSION_SECRET` | `change-me-in-local-dev-only` |
| oidc issuer | `OPENAUTHING_OIDC_ISSUER` | `http://localhost:8080` |
| oidc signing key file | `OPENAUTHING_OIDC_SIGNING_KEY_FILE` | `./deploy/keys/oidc-signing.pem` |
| oidc authorization code ttl | `OPENAUTHING_OIDC_AUTHORIZATION_CODE_TTL_SECONDS` | `300` |
| saml idp entity id | `OPENAUTHING_SAML_IDP_ENTITY_ID` | `http://localhost:8080/saml/idp/metadata` |
| saml certificate file | `OPENAUTHING_SAML_IDP_CERT_FILE` | `./deploy/keys/saml-idp-cert.pem` |
| saml private key file | `OPENAUTHING_SAML_IDP_KEY_FILE` | `./deploy/keys/saml-idp-key.pem` |
| config file path | `OPENAUTHING_CONFIG_FILE` | `./config.example.json` |

参考：

- [`.env.example`](./.env.example)
- [`config.example.json`](./config.example.json)

## HTTP 接口

基础接口：

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/ping`
- `GET /.well-known/openid-configuration`
- `GET /.well-known/jwks.json`
- `GET /oauth2/authorize`
- `POST /oauth2/token`
- `GET /oauth2/userinfo`
- `POST /oauth2/revoke`
- `GET /oauth2/logout`
- `POST /oauth2/logout`
- `GET /saml/idp/metadata`
- `GET /saml/idp/login`
- `GET /saml/idp/sso`
- `POST /saml/idp/sso`
- `GET /saml/idp/slo`
- `POST /saml/idp/slo`

本任务新增 CRUD：

- `POST /api/v1/auth/login`
- `GET /api/v1/auth/me`
- `POST /api/v1/auth/logout`
- `GET /api/v1/sessions`
- `POST /api/v1/sessions/:id/revoke`
- `GET /api/v1/users`
- `POST /api/v1/users`
- `GET /api/v1/users/:id`
- `PUT /api/v1/users/:id`
- `GET /api/v1/groups`
- `POST /api/v1/groups`
- `GET /api/v1/roles`
- `POST /api/v1/roles`
- `GET /api/v1/apps`
- `POST /api/v1/apps`
- `GET /api/v1/apps/:id/saml`
- `PUT /api/v1/apps/:id/saml`
- `POST /api/v1/apps/:id/saml/import-metadata`

### 统一成功响应

```json
{
  "request_id": "a7d5678f3e6b45dbbc411d7da08ea6fd",
  "data": {
    "message": "pong"
  }
}
```

### 统一错误响应

```json
{
  "request_id": "a7d5678f3e6b45dbbc411d7da08ea6fd",
  "error": {
    "code": "validation_error",
    "message": "request validation failed",
    "details": {
      "fields": {
        "username": "is required"
      }
    }
  }
}
```

## API 使用示例

### OIDC Discovery

```bash
curl http://localhost:8080/.well-known/openid-configuration
```

返回的 metadata 当前至少包含：

- `issuer`
- `authorization_endpoint`
- `token_endpoint`
- `userinfo_endpoint`
- `jwks_uri`
- `response_types_supported`
- `subject_types_supported`
- `id_token_signing_alg_values_supported`
- `scopes_supported`
- `claims_supported`

### OIDC JWKS

```bash
curl http://localhost:8080/.well-known/jwks.json
```

说明：当前只提供 `RS256` 签名公钥。若未配置 `OPENAUTHING_OIDC_SIGNING_KEY_FILE`，服务启动时会生成一把仅当前进程可用的临时 RSA 私钥；重启后 `kid` 会变化，只适合本地开发。

### SAML IdP Metadata

```bash
curl http://localhost:8080/saml/idp/metadata
```

说明：

- 当前返回标准 XML metadata
- 默认会输出 `entityID`、`SingleSignOnService`、`SingleLogoutService` 和签名证书
- 若未配置 `OPENAUTHING_SAML_IDP_CERT_FILE` / `OPENAUTHING_SAML_IDP_KEY_FILE`，服务启动时会自动生成一张仅当前进程可用的开发证书
- 生产环境建议显式配置固定证书与私钥文件，避免重启后证书变化

### 保存 SAML SP 配置

```bash
curl -X PUT http://localhost:8080/api/v1/apps/APP_ID/saml \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "https://sp.example.test/metadata",
    "acs_url": "https://sp.example.test/saml/acs",
    "slo_url": "https://sp.example.test/saml/slo",
    "nameid_format": "urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress",
    "want_assertions_signed": true,
    "want_response_signed": false,
    "sign_authn_request": false,
    "encrypt_assertion": false,
    "attribute_mapping": {
      "username": "preferred_username",
      "email": "email",
      "name": "name"
    }
  }'
```

### 导入 SAML SP Metadata

```bash
curl -X POST http://localhost:8080/api/v1/apps/APP_ID/saml/import-metadata \
  -H "Content-Type: application/json" \
  -d '{
    "metadata_xml": "<EntityDescriptor>...</EntityDescriptor>"
  }'
```

说明：

- 当前会解析 `entity_id`、`AssertionConsumerService`、`SingleLogoutService`、`NameIDFormat`
- 会解析 `WantAssertionsSigned`、`AuthnRequestsSigned`
- 会提取首个 `X509Certificate`
- metadata 解析失败时会返回统一 JSON 错误，并把错误挂到 `metadata_xml` 字段

### SAML 2.0 SP-Initiated / IdP-Initiated SSO 联调

先准备一个 `type=saml-sp` 的应用，并写入 SAML SP 配置：

```bash
curl -X POST http://localhost:8080/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "name": "SAML Demo",
    "code": "saml-demo",
    "type": "saml-sp",
    "status": "active",
    "homepage_url": "https://sp.example.test",
    "description": "SAML demo app"
  }'
```

```bash
curl -X PUT http://localhost:8080/api/v1/apps/APP_ID/saml \
  -H "Content-Type: application/json" \
  -d '{
    "entity_id": "https://sp.example.test/metadata",
    "acs_url": "https://sp.example.test/saml/acs",
    "slo_url": "https://sp.example.test/saml/slo",
    "nameid_format": "persistent",
    "want_assertions_signed": true,
    "want_response_signed": false,
    "sign_authn_request": false,
    "encrypt_assertion": false,
    "attribute_mapping": {
      "username": "preferred_username",
      "email": "email",
      "name": "name",
      "groups": "groups"
    }
  }'
```

使用本地账号先登录 openauthing，拿到中心 session cookie：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret123"
  }'
```

IdP-Initiated SSO：

```bash
curl -i -c cookies.txt -b cookies.txt \
  "http://localhost:8080/saml/idp/login?app_id=APP_ID"
```

成功后会返回一个自动提交到 ACS 的 HTML 表单，表单里至少包含：

- `SAMLResponse`
- `RelayState`（如果有）

SP-Initiated SSO：

1. SP 把 `AuthnRequest` 以 HTTP-Redirect 或 HTTP-POST 发到 `/saml/idp/sso`
2. 如果当前没有中心 session，openauthing 会先跳到 `/saml/idp/login`
3. 本地登录成功后，浏览器会继续原始 SAML 请求
4. openauthing 会签发带签名的 Assertion，并通过 HTTP-POST 回传到已注册的 ACS URL

当前 Assertion 默认会带这些属性：

- `username`
- `email`
- `name`
- `groups`

属性名可通过 `attribute_mapping` 覆盖。NameID 当前支持：

- `persistent`
- `emailAddress`
- `unspecified`

### SAML 2.0 Single Logout 基础联调

当前版本的 SLO 目标是先打通最小可用链路：

- 支持 SP 通过 `GET /saml/idp/slo` 或 `POST /saml/idp/slo` 发起 `LogoutRequest`
- openauthing 会按 `session_index` 或 `name_id` 检索已建立的 `saml_login_sessions`
- 匹配成功后会联动注销中心会话 `auth_sessions`
- 同时把绑定的 SAML 登录态标记为 `logged_out`
- 最后生成签名的 `LogoutResponse`，并通过自动提交的 HTML form 回传到已注册的 `slo_url`

最小联调步骤：

1. 先按上面的 SSO 步骤完成一次登录，让 openauthing 建立中心 session 和 `saml_login_sessions`
2. 让 SP 发送 `LogoutRequest` 到 `/saml/idp/slo`
3. openauthing 会清理当前浏览器里的 `openauthing_session` cookie
4. openauthing 会返回一个自动提交到 SP `SingleLogoutService` 的 HTML 表单，表单中至少包含：
   - `SAMLResponse`
   - `RelayState`（如果请求里有）
5. SLO 完成后，再访问 `/api/v1/auth/me` 应返回未登录

说明：

- 当前会把 SAML `SessionIndex` 绑定为中心会话 `auth_sessions.id`
- 当前支持通过 `session_index` 或 `name_id` 查找 SAML 登录态
- 当前只实现 SP 发起到 IdP 的基础 SLO 处理；如果用户直接调用 `/api/v1/auth/logout`，还不会反向通知已登录的 SAML SP
- 当前为未来统一登出保留了协议适配接口，但还没有实现多协议 fan-out 登出编排
- 当前没有实现 AuthnRequest / LogoutRequest 的签名校验，也没有实现完整的前后端多 SP 级联登出

### OIDC Authorization Code + PKCE 本地联调

先写入一个最小 public client：

```bash
docker compose exec -T postgres psql -U openauthing -d openauthing -f /scripts/seed_oidc_public_client.sql
```

这个 seed 会创建：

- tenant: `10000000-0000-0000-0000-000000000001`
- public client: `openauthing-demo-public`
- redirect uri: `http://localhost:5173/callback`

再创建一个测试用户：

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "10000000-0000-0000-0000-000000000001",
    "username": "alice",
    "email": "alice@example.com",
    "display_name": "Alice",
    "password": "secret123",
    "status": "active",
    "source": "local"
  }'
```

登录拿中心 session cookie：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret123"
  }'
```

生成 PKCE challenge，然后请求授权端点：

```bash
verifier="verifier-value-1234567890"
challenge="$(printf '%s' "$verifier" \
  | openssl dgst -binary -sha256 \
  | openssl base64 -A \
  | tr '+/' '-_' \
  | tr -d '=')"
curl -i -c cookies.txt -b cookies.txt \
  "http://localhost:8080/oauth2/authorize?response_type=code&client_id=openauthing-demo-public&redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback&scope=openid%20profile%20email&state=demo-state&code_challenge=$challenge&code_challenge_method=S256"
```

从 `Location` 里取出 `code` 后换 token：

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=authorization_code&client_id=openauthing-demo-public&code=REPLACE_CODE&redirect_uri=http://localhost:5173/callback&code_verifier=verifier-value-1234567890"
```

成功后会返回：

- `access_token`
- `id_token`
- `refresh_token`
- `token_type`
- `expires_in`
- `scope`

用 access token 调 `userinfo`：

```bash
curl http://localhost:8080/oauth2/userinfo \
  -H "Authorization: Bearer REPLACE_ACCESS_TOKEN"
```

用 refresh token 刷新：

```bash
curl -X POST http://localhost:8080/oauth2/token \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "grant_type=refresh_token&client_id=openauthing-demo-public&refresh_token=REPLACE_REFRESH_TOKEN"
```

说明：refresh token 会执行 rotation。刷新成功后会返回新的 `refresh_token`，旧 token 再次使用会被判定为重放并撤销该中心 session 关联的 OIDC token。

撤销 token：

```bash
curl -X POST http://localhost:8080/oauth2/revoke \
  -H "Content-Type: application/x-www-form-urlencoded" \
  -d "client_id=openauthing-demo-public&token=REPLACE_REFRESH_TOKEN&token_type_hint=refresh_token"
```

OIDC logout：

```bash
curl -i -X GET -c cookies.txt -b cookies.txt \
  "http://localhost:8080/oauth2/logout?client_id=openauthing-demo-public&post_logout_redirect_uri=http%3A%2F%2Flocalhost%3A5173%2Fcallback"
```

说明：`/oauth2/logout` 会同时销毁中心 session、清理浏览器中的 `openauthing_session` cookie，并撤销当前中心 session 关联的 OIDC access token / refresh token。

### 创建用户

```bash
curl -X POST http://localhost:8080/api/v1/users \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "username": "alice",
    "email": "alice@example.com",
    "display_name": "Alice",
    "password": "secret123",
    "status": "active",
    "source": "local"
  }'
```

说明：如果提供 `password`，服务端会使用 Argon2id 生成 `password_hash` 并入库；接口响应不会回传 `password_hash`。如需导入已有哈希值，仍可直接传 `password_hash`，但必须是合法的 Argon2id 编码串。

### 本地密码登录

用户名登录：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "username": "alice",
    "password": "secret123"
  }'
```

邮箱登录：

```bash
curl -X POST http://localhost:8080/api/v1/auth/login \
  -c cookies.txt -b cookies.txt \
  -H "Content-Type: application/json" \
  -d '{
    "email": "alice@example.com",
    "password": "secret123"
  }'
```

说明：登录接口当前带内存版限流占位，主要用于后续接入 Redis 限流前的最小保护。
说明：登录成功后会下发 `openauthing_session` cookie。cookie 中保存原始 sid，数据库 `auth_sessions.sid` 中保存的是 sid 的 HMAC-SHA256 哈希值。

### 读取当前会话

```bash
curl -c cookies.txt -b cookies.txt \
  http://localhost:8080/api/v1/auth/me
```

### 列出当前用户会话

```bash
curl -c cookies.txt -b cookies.txt \
  http://localhost:8080/api/v1/sessions
```

### 撤销指定会话

```bash
curl -X POST -c cookies.txt -b cookies.txt \
  http://localhost:8080/api/v1/sessions/SESSION_ID/revoke
```

### 登出当前会话

```bash
curl -X POST -c cookies.txt -b cookies.txt \
  http://localhost:8080/api/v1/auth/logout
```

### 查询用户列表

```bash
curl "http://localhost:8080/api/v1/users?tenant_id=11111111-1111-1111-1111-111111111111&username=ali&status=active&limit=20&offset=0"
```

### 查询单个用户

```bash
curl "http://localhost:8080/api/v1/users/22222222-2222-2222-2222-222222222222"
```

### 更新用户

```bash
curl -X PUT http://localhost:8080/api/v1/users/22222222-2222-2222-2222-222222222222 \
  -H "Content-Type: application/json" \
  -d '{
    "display_name": "Alice Admin",
    "status": "disabled"
  }'
```

### 创建组

```bash
curl -X POST http://localhost:8080/api/v1/groups \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "name": "Platform",
    "code": "platform",
    "description": "Platform team"
  }'
```

### 创建角色

```bash
curl -X POST http://localhost:8080/api/v1/roles \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "name": "Tenant Admin",
    "code": "tenant_admin",
    "description": "Tenant administrator"
  }'
```

### 创建应用

```bash
curl -X POST http://localhost:8080/api/v1/apps \
  -H "Content-Type: application/json" \
  -d '{
    "tenant_id": "11111111-1111-1111-1111-111111111111",
    "name": "Admin Console",
    "code": "admin-console",
    "type": "oidc-client",
    "status": "active",
    "homepage_url": "https://admin.example.test",
    "icon_url": "https://admin.example.test/icon.png",
    "description": "Admin frontend"
  }'
```

### 列表过滤

- users：`tenant_id`、`username`、`email`、`status`
- groups：`tenant_id`、`name`、`code`
- roles：`tenant_id`、`name`、`code`
- apps：`tenant_id`、`name`、`code`、`type`、`status`

列表接口统一支持：

- `limit`
- `offset`

## 分层设计

- `domain`：实体模型和输入模型
- `repo`：仓储接口和 Postgres 实现
- `service`：输入校验、默认值填充、错误映射
- `handler`：HTTP 解码、查询参数处理、统一 JSON 响应
- `store/postgres`：数据库连接、事务上下文和 `DBTX` 抽象

Repo 层支持事务上下文。当前通过 `store.WithinTx(ctx, fn)` 将 `sql.Tx` 绑定到 `context.Context`，repo 在有事务上下文时优先走事务执行器。

## Migration

当前 migration 文件：

- [`000001_init.up.sql`](./migrations/000001_init.up.sql)
- [`000001_init.down.sql`](./migrations/000001_init.down.sql)
- [`000002_runtime_baseline.up.sql`](./migrations/000002_runtime_baseline.up.sql)
- [`000002_runtime_baseline.down.sql`](./migrations/000002_runtime_baseline.down.sql)
- [`000003_core_identity.up.sql`](./migrations/000003_core_identity.up.sql)
- [`000003_core_identity.down.sql`](./migrations/000003_core_identity.down.sql)
- [`000004_crud_api_baseline.up.sql`](./migrations/000004_crud_api_baseline.up.sql)
- [`000004_crud_api_baseline.down.sql`](./migrations/000004_crud_api_baseline.down.sql)
- [`000005_auth_login_baseline.up.sql`](./migrations/000005_auth_login_baseline.up.sql)
- [`000005_auth_login_baseline.down.sql`](./migrations/000005_auth_login_baseline.down.sql)
- [`000006_auth_sessions.up.sql`](./migrations/000006_auth_sessions.up.sql)
- [`000006_auth_sessions.down.sql`](./migrations/000006_auth_sessions.down.sql)
- [`000007_oidc_discovery_baseline.up.sql`](./migrations/000007_oidc_discovery_baseline.up.sql)
- [`000007_oidc_discovery_baseline.down.sql`](./migrations/000007_oidc_discovery_baseline.down.sql)
- [`000008_oidc_code_flow.up.sql`](./migrations/000008_oidc_code_flow.up.sql)
- [`000008_oidc_code_flow.down.sql`](./migrations/000008_oidc_code_flow.down.sql)
- [`000009_oidc_runtime_tokens.up.sql`](./migrations/000009_oidc_runtime_tokens.up.sql)
- [`000009_oidc_runtime_tokens.down.sql`](./migrations/000009_oidc_runtime_tokens.down.sql)
- [`000010_examples_jenkins_oidc.up.sql`](./migrations/000010_examples_jenkins_oidc.up.sql)
- [`000010_examples_jenkins_oidc.down.sql`](./migrations/000010_examples_jenkins_oidc.down.sql)
- [`000011_examples_jumpserver_oidc.up.sql`](./migrations/000011_examples_jumpserver_oidc.up.sql)
- [`000011_examples_jumpserver_oidc.down.sql`](./migrations/000011_examples_jumpserver_oidc.down.sql)
- [`000012_saml_service_providers.up.sql`](./migrations/000012_saml_service_providers.up.sql)
- [`000012_saml_service_providers.down.sql`](./migrations/000012_saml_service_providers.down.sql)
- [`000013_saml_sso_flow.up.sql`](./migrations/000013_saml_sso_flow.up.sql)
- [`000013_saml_sso_flow.down.sql`](./migrations/000013_saml_sso_flow.down.sql)
- [`000014_saml_login_sessions.up.sql`](./migrations/000014_saml_login_sessions.up.sql)
- [`000014_saml_login_sessions.down.sql`](./migrations/000014_saml_login_sessions.down.sql)
- [`000015_examples_aws_iam_identity_center.up.sql`](./migrations/000015_examples_aws_iam_identity_center.up.sql)
- [`000015_examples_aws_iam_identity_center.down.sql`](./migrations/000015_examples_aws_iam_identity_center.down.sql)
- [`000016_examples_alicloud_cloudsso.up.sql`](./migrations/000016_examples_alicloud_cloudsso.up.sql)
- [`000016_examples_alicloud_cloudsso.down.sql`](./migrations/000016_examples_alicloud_cloudsso.down.sql)
- [`000017_examples_mock_saml_sp.up.sql`](./migrations/000017_examples_mock_saml_sp.up.sql)
- [`000017_examples_mock_saml_sp.down.sql`](./migrations/000017_examples_mock_saml_sp.down.sql)

执行：

```bash
make migrate-up
make migrate-down
```

验证 migration：

```bash
pwsh ./scripts/verify_migrations.ps1
```

## 本地启动

### Docker Compose

```bash
docker compose up --build
```

启动后可访问：

- [http://localhost:8080/healthz](http://localhost:8080/healthz)
- [http://localhost:8080/readyz](http://localhost:8080/readyz)
- [http://localhost:8080/api/v1/ping](http://localhost:8080/api/v1/ping)
- [http://localhost:5173](http://localhost:5173)

### Makefile

```bash
make dev
make build
make test
make migrate-up
make migrate-down
```

## Jenkins OIDC 联调样例

仓库已提供可复现的 Jenkins OIDC 示例目录：

- [`examples/jenkins-oidc/docker-compose.yml`](./examples/jenkins-oidc/docker-compose.yml)
- [`examples/jenkins-oidc/scripts/bootstrap.ps1`](./examples/jenkins-oidc/scripts/bootstrap.ps1)
- [`examples/jenkins-oidc/seed/jenkins_oidc_seed.sql`](./examples/jenkins-oidc/seed/jenkins_oidc_seed.sql)
- [`examples/jenkins-oidc/README.md`](./examples/jenkins-oidc/README.md)

这个示例会启动：

- `openauthing`
- `jenkins`
- `postgres`
- `redis`

并自动完成：

- 执行全部 migration
- 创建 Jenkins 演示 tenant / application / OIDC client
- 创建演示测试用户

启动命令：

```bash
pwsh ./examples/jenkins-oidc/scripts/bootstrap.ps1
```

启动后默认访问地址：

- openauthing: [http://localhost:8080](http://localhost:8080)
- Jenkins: [http://localhost:8081](http://localhost:8081)

Jenkins 侧需要安装并启用的插件、OIDC 字段映射、回调地址和常见错误排查，见：

- [`examples/jenkins-oidc/README.md`](./examples/jenkins-oidc/README.md)

## JumpServer OIDC 联调样例

仓库已提供 JumpServer OIDC 示例目录：

- [`examples/jumpserver-oidc/docker-compose.yml`](./examples/jumpserver-oidc/docker-compose.yml)
- [`examples/jumpserver-oidc/scripts/bootstrap.ps1`](./examples/jumpserver-oidc/scripts/bootstrap.ps1)
- [`examples/jumpserver-oidc/seed/jumpserver_oidc_seed.sql`](./examples/jumpserver-oidc/seed/jumpserver_oidc_seed.sql)
- [`examples/jumpserver-oidc/jumpserver-config.txt.example`](./examples/jumpserver-oidc/jumpserver-config.txt.example)
- [`examples/jumpserver-oidc/README.md`](./examples/jumpserver-oidc/README.md)

这个示例会启动：

- `openauthing`
- `postgres`
- `redis`

并自动完成：

- 执行全部 migration
- 创建 JumpServer 演示 tenant / application / OIDC client
- 创建演示测试用户
- 绑定演示 `groups / roles` claim

启动命令：

```bash
pwsh ./examples/jumpserver-oidc/scripts/bootstrap.ps1
```

说明：

- 这个示例不额外启动 JumpServer，本任务提供 openauthing 侧联调环境和 JumpServer 配置模板
- JumpServer 侧字段、回调地址、首次登录策略和常见错误排查，见：
  [`examples/jumpserver-oidc/README.md`](./examples/jumpserver-oidc/README.md)

## AWS IAM Identity Center 对接样例

仓库已提供 AWS IAM Identity Center 示例目录：

- [`examples/aws-iam-identity-center/docker-compose.yml`](./examples/aws-iam-identity-center/docker-compose.yml)
- [`examples/aws-iam-identity-center/aws-iam-identity-center.env.example`](./examples/aws-iam-identity-center/aws-iam-identity-center.env.example)
- [`examples/aws-iam-identity-center/seed/aws_iam_identity_center_seed.sql`](./examples/aws-iam-identity-center/seed/aws_iam_identity_center_seed.sql)
- [`examples/aws-iam-identity-center/scripts/bootstrap.sh`](./examples/aws-iam-identity-center/scripts/bootstrap.sh)
- [`examples/aws-iam-identity-center/README.md`](./examples/aws-iam-identity-center/README.md)

这个示例会启动：

- `openauthing`
- `postgres`
- `redis`

并准备：

- 一个 `saml-sp` 类型应用，用于 AWS IAM Identity Center 作为 SP 的 SAML 登录配置
- 一个 `scim-target` 类型应用，用于 AWS IAM Identity Center 的 SCIM 对接占位
- 一个测试用户和一个测试组

Linux 启动命令：

```bash
bash ./examples/aws-iam-identity-center/scripts/bootstrap.sh
```

说明：

- 这个示例以文档、seed 和配置模板为主，不会自动调用 AWS API
- 示例会要求你把 AWS 控制台里下载的 metadata 和 SCIM endpoint/token 手工填回本地 env 文件
- 当前 `scim-target` 只是配置准备；openauthing 还没有在本任务里实现真正的 SCIM 出站同步

## 阿里云 CloudSSO 对接样例

仓库已提供 Alibaba Cloud CloudSSO 示例目录：

- [`examples/alicloud-cloudsso/docker-compose.yml`](./examples/alicloud-cloudsso/docker-compose.yml)
- [`examples/alicloud-cloudsso/alicloud-cloudsso.env.example`](./examples/alicloud-cloudsso/alicloud-cloudsso.env.example)
- [`examples/alicloud-cloudsso/seed/alicloud_cloudsso_seed.sql`](./examples/alicloud-cloudsso/seed/alicloud_cloudsso_seed.sql)
- [`examples/alicloud-cloudsso/scripts/bootstrap.sh`](./examples/alicloud-cloudsso/scripts/bootstrap.sh)
- [`examples/alicloud-cloudsso/README.md`](./examples/alicloud-cloudsso/README.md)

这个示例会启动：

- `openauthing`
- `postgres`
- `redis`

并准备：

- 一个 `saml-sp` 类型应用，用于阿里云 CloudSSO 作为 SP 的 SAML 登录配置
- 一个 `scim-target` 类型应用，用于阿里云 CloudSSO 的 SCIM 对接占位
- 一个测试用户和一个测试组

Linux 启动命令：

```bash
bash ./examples/alicloud-cloudsso/scripts/bootstrap.sh
```

说明：

- 这个示例以文档、seed 和配置模板为主，不会自动调用阿里云 API
- 示例会要求你把 CloudSSO 控制台里的 `Entity ID`、`ACS URL`、`SCIM Endpoint` 和本地保存的 `SCIM token` 手工填回 env 文件
- 当前 `scim-target` 只是配置准备；openauthing 还没有实现真正的 SCIM 出站同步

## Mock SAML SP 本地联调样例

仓库已提供 Mock SAML SP 示例目录：

- [`examples/mock-saml-sp/docker-compose.yml`](./examples/mock-saml-sp/docker-compose.yml)
- [`examples/mock-saml-sp/mock-saml-sp.env.example`](./examples/mock-saml-sp/mock-saml-sp.env.example)
- [`examples/mock-saml-sp/scripts/bootstrap.sh`](./examples/mock-saml-sp/scripts/bootstrap.sh)
- [`examples/mock-saml-sp/seed/mock_saml_sp_seed.sql`](./examples/mock-saml-sp/seed/mock_saml_sp_seed.sql)
- [`examples/mock-saml-sp/README.md`](./examples/mock-saml-sp/README.md)

这个示例会启动：

- `openauthing`
- `mock-saml-sp`
- `postgres`
- `redis`

并准备：

- 一个 `saml-sp` 类型应用，指向本地 Mock SP 的 ACS
- 一个测试用户和一个测试组
- 一个最小可用的 Mock SP 页面，用来发起 `AuthnRequest`、接收 `SAMLResponse` 并展示解析后的 `Assertion`

Linux 启动命令：

```bash
bash ./examples/mock-saml-sp/scripts/bootstrap.sh
```

说明：

- 这个示例以本地联调和 Assertion 调试为主
- Mock SP 会展示 `NameID`、`Attributes`、`RelayState` 和最小 XML Signature 验证结果
- 这个示例不追求生产级 SP 功能完整性

## 测试

当前测试覆盖：

- 配置文件读取与环境变量覆盖
- `/healthz`、`/readyz`、`/api/v1/ping`
- recovery 统一错误返回
- access log 包含 `request_id`
- user repo 事务上下文与过滤查询
- user service 校验和错误映射
- user handler 基础创建接口
- Argon2id 密码 hash / verify
- auth login service 成功 / 失败 / 限流
- auth login handler
- auth session repo / middleware / me / logout / revoke
- SAML IdP metadata 输出、SP metadata 导入、SP-Initiated / IdP-Initiated SSO、SAML 登录态绑定和基础 SLO
- Jenkins OIDC example 资产校验
- JumpServer OIDC example 资产校验
- AWS IAM Identity Center example 资产校验
- Alibaba Cloud CloudSSO example 资产校验
- Mock SAML SP example 资产校验
- migration 验证脚本检查核心表和唯一索引

执行：

```bash
make test
```

额外验证 migration：

```bash
pwsh ./scripts/verify_migrations.ps1
```

## 当前限制

- 当前中心 session 仍以数据库 + HttpOnly cookie 为主；OIDC access token / id token 已签发 JWT，并已支持 `userinfo`、`revoke`、`logout` 和 refresh token rotation，但协议级前后端联动单点登出还未实现
- 当前已实现 OIDC Discovery、JWKS、Authorization Code + PKCE、refresh token grant、token revoke 和 RP 发起的基础 logout，但动态 client 注册、consent 页面、`id_token_hint` 校验和更完整的 session family 风险处置还未实现
- 当前 SAML 已实现 IdP metadata、SP metadata 导入、SP 配置管理、SP-Initiated / IdP-Initiated SSO、Assertion 签名和基础 Single Logout，但还没有 AuthnRequest / LogoutRequest 签名校验、中心 logout 反向 fan-out、完整多 SP 统一登出编排、加密 Assertion 和更细的属性策略
- 当前 `scim-target` 应用类型已经可以用于记录外部 SCIM 目标，但 openauthing 还没有实现完整的 SCIM v2 出站同步，所以 AWS IAM Identity Center 样例当前仍以配置准备和字段契约为主
- groups / roles / apps 暂时只实现列表和创建，未实现按 id 查询和更新
- 当前登录接口按全局 `username` 或 `email` 查找；如果多租户下出现重复标识，会拒绝登录并在服务端记录审计日志
- `/readyz` 仍然只检查关键配置是否存在，不做真实数据库连通性探测
- TODO：后续任务再补 OIDC `userinfo` 扩展 claims、`id_token_hint` / front-channel logout、SAML / CAS 的授权流程、会话映射和 Redis 会话缓存
