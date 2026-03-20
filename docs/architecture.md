# openauthing 架构基线

## 核心原则

- 采用模块化单体，先统一模型、会话和审计，再逐步增加协议实现
- 协议层不直接拥有用户源，统一依赖 `usercenter`、`authcore`、`apps`
- 管理后台和用户门户共用同一后端 API 边界，但前端应用分开维护

## 模块边界

### `usercenter`

负责租户、组织、用户、组、角色、权限的领域模型和管理 API。

### `authcore`

负责本地认证、密码策略、中心会话、MFA、登录风控入口。

### `apps`

负责应用注册、应用协议配置、属性映射和接入策略。

### `oidc` / `saml` / `cas` / `ldap` / `scim`

负责各协议的适配层实现，但底层统一复用用户、会话、应用配置和审计能力。

### `audit`

负责管理面和协议面的安全审计事件落库与检索。

### `policy`

负责后台 RBAC 与未来的属性映射规则装配。

### `shared`

负责公共响应、错误模型、基础类型、跨模块工具函数。

## 当前目录映射

```text
cmd/server
internal/config
internal/server
internal/shared
migrations
web/admin
web/portal
docs
```

## 阶段依赖

```text
Phase 1 基础框架
  -> Phase 2 Auth Core
    -> Phase 3 OIDC
    -> Phase 4 SAML
      -> Phase 5 CAS
      -> Phase 6 LDAP
        -> Phase 7 SCIM
          -> Phase 8 增强
```

## Phase 1 当前基线

- 服务入口已经固定为 `cmd/server`
- 环境配置已集中在 `internal/config`
- HTTP 健康检查和元信息接口已就位
- PostgreSQL 初始 migration 已覆盖租户、组织、用户、RBAC、应用、审计

## 后续落地顺序

1. 加入 PostgreSQL 与 Redis 真连接
2. 建立后台登录与会话 API
3. 建立 RBAC 中间件与平台默认角色
4. 补 Vue Admin 基础壳
5. 再进入协议层开发
