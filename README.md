# openauthing

`openauthing` 是一个自建统一认证平台，目标是以模块化单体方式逐步交付用户中心、统一会话、OIDC、SAML、CAS、LDAP、SCIM 2.0 和管理控制台。

当前仓库已经按设计文档启动 Phase 1 基础框架，先把后续协议层依赖的公共基线稳定下来。

## 当前已落地

- Go 服务入口：`cmd/server`
- 基础配置加载：环境变量方式
- HTTP 基线接口：`/healthz`、`/readyz`、`/api/v1/meta`
- Phase 1 核心 PostgreSQL migration 草案
- 阶段开发说明：`docs/phases.md`
- 模块职责说明：`docs/architecture.md`
- 前端目录占位：`web/admin`、`web/portal`

## 开发原则

- 架构优先采用模块化单体，不先拆微服务
- Phase 1 先稳定用户中心、应用模型、配置和管理面骨架
- 协议层按 OIDC -> SAML -> CAS -> LDAP -> SCIM 顺序推进
- 每个阶段都要求仓库保持可运行或可继续接手的状态

## 仓库结构

```text
cmd/server            Go 服务启动入口
internal/config       配置加载
internal/server       HTTP 服务与路由基线
internal/shared       通用响应封装
migrations            PostgreSQL migration
docs                  架构与阶段说明
web/admin             管理后台占位
web/portal            用户门户占位
```

## 本地启动基线

1. 安装 Go 1.24+
2. 参考 `.env.example` 配置环境变量
3. 使用你选定的 migration 工具执行 `migrations/`
4. 启动服务：`go run ./cmd/server`

当前基线接口：

- `GET /healthz`
- `GET /readyz`
- `GET /api/v1/meta`

## 阶段路线

- [阶段开发说明](docs/phases.md)
- [架构基线](docs/architecture.md)

## 下一步

Phase 1 剩余重点是：

- PostgreSQL / Redis 真连接接入
- 后台登录 API
- RBAC 中间件与权限模型落地
- Vue Admin 基础壳和登录页
