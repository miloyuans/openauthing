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
| config file path | `OPENAUTHING_CONFIG_FILE` | `./config.example.json` |

参考：

- [`.env.example`](./.env.example)
- [`config.example.json`](./config.example.json)

## HTTP 接口

基础接口：

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/ping`

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

执行：

```bash
make migrate-up
make migrate-down
```

验证 migration：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify_migrations.ps1
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
- migration 验证脚本检查核心表和唯一索引

执行：

```bash
make test
```

额外验证 migration：

```powershell
powershell -ExecutionPolicy Bypass -File .\scripts\verify_migrations.ps1
```

## 当前限制

- 当前已实现中心 session 和 HttpOnly cookie，但还没有 JWT 或协议级单点登出
- groups / roles / apps 暂时只实现列表和创建，未实现按 id 查询和更新
- 当前登录接口按全局 `username` 或 `email` 查找；如果多租户下出现重复标识，会拒绝登录并在服务端记录审计日志
- `/readyz` 仍然只检查关键配置是否存在，不做真实数据库连通性探测
- TODO：后续任务再补 OIDC / SAML / CAS 的会话映射、单点登出和 Redis 会话缓存
