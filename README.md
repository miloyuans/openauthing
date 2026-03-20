# openauthing

`openauthing` 是一个自建统一认证平台。当前仓库已经具备后续模块开发所需的基础运行框架：配置系统、结构化日志、统一错误返回、基础中间件、最小 HTTP 接口、Vue 管理后台骨架、Docker Compose 和 Makefile。

本任务仍然不引入任何业务逻辑，只打底运行能力。

## 目录结构

```text
cmd/server
internal/config
internal/logging
internal/platform
internal/server
internal/shared
migrations
web/admin
deploy/docker
docs
```

## 配置系统

配置支持两种来源，优先级为：

1. 环境变量
2. 本地 JSON 配置文件
3. 代码默认值

如果设置了 `OPENAUTHING_CONFIG_FILE`，服务会先读取该文件，再用环境变量覆盖同名配置。

### 当前支持的配置项

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

- [.env.example](./.env.example)
- [config.example.json](./config.example.json)

## HTTP 基线

当前后端提供以下接口：

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/ping`

统一成功响应：

```json
{
  "request_id": "a7d5678f3e6b45dbbc411d7da08ea6fd",
  "data": {
    "message": "pong"
  }
}
```

统一错误响应：

```json
{
  "request_id": "a7d5678f3e6b45dbbc411d7da08ea6fd",
  "error": {
    "code": "internal_error",
    "message": "internal server error"
  }
}
```

## 中间件

当前已接入：

- `request_id`
- `recovery`
- `access log`
- `cors`
- `auth` 占位中间件

请求日志为结构化 JSON，包含：

- `request_id`
- `method`
- `path`
- `status`
- `latency_ms`

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

- 配置文件读取
- 环境变量覆盖配置文件
- `/healthz`
- `/readyz`
- `/api/v1/ping`
- recovery 统一错误返回
- access log 包含 `request_id`、`method`、`path`、`status`、`latency_ms`

执行：

```bash
make test
```

## Migration

本任务没有数据库 schema 变更，但按任务约定提供了可回滚 migration 占位：

- [000001_init.up.sql](./migrations/000001_init.up.sql)
- [000001_init.down.sql](./migrations/000001_init.down.sql)
- [000002_runtime_baseline.up.sql](./migrations/000002_runtime_baseline.up.sql)
- [000002_runtime_baseline.down.sql](./migrations/000002_runtime_baseline.down.sql)

## 验收

1. 执行 `docker compose up --build`
2. 访问 `http://localhost:8080/api/v1/ping`
3. 观察后端日志，确认包含 `request_id`
4. 访问 `http://localhost:8080/readyz`
5. 执行 `make test`

## 当前限制

- `auth middleware` 目前只是占位，不做真实认证
- `/readyz` 目前只检查关键配置是否存在，不做真实连通性探测
- `session secret` 目前只用于配置基线，后续任务再接入真实 session 能力
- TODO：后续接入 zap 或继续沿用 `slog` 的统一日志封装策略时，再评估扩展字段和日志采样
