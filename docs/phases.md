# openauthing 阶段开发说明

## 总体节奏

项目按设计文档拆成 8 个阶段，每个阶段都要求满足两个条件：

- 仓库结构继续可扩展，不因为临时实现破坏模块边界
- 当前阶段交付物能作为下一阶段的稳定依赖

## Phase 1 基础框架

目标：把工程骨架、配置、核心数据模型和管理面入口稳定下来。

当前已落地：

- Go 服务入口与 HTTP 基线
- 环境变量配置加载
- PostgreSQL 核心表 migration 草案
- 架构与阶段文档

当前待完成：

- PostgreSQL / Redis 真连接
- 后台登录 API
- RBAC 中间件
- `web/admin` 初始 Vue 工程

阶段完成标准：

- 服务可以启动并暴露健康检查
- migration 可执行
- 后台管理员可以登录
- RBAC 能限制管理 API 访问

## Phase 2 Auth Core

目标：完成本地账号认证、密码重置、中心会话、审计日志、用户门户基线。

重点输出：

- 本地账号登录
- 密码重置
- 中心会话管理
- 登录审计
- 用户门户基础页

## Phase 3 OIDC

目标：交付可对接 Jenkins / JumpServer 的 OIDC Provider。

重点输出：

- Discovery
- Authorize / Token / UserInfo / JWKS
- Authorization Code + PKCE
- OIDC Client 管理
- Jenkins / JumpServer 对接样例

## Phase 4 SAML

目标：交付可对接 AWS / 阿里云的 SAML IdP。

重点输出：

- Metadata
- SP-Initiated / IdP-Initiated
- Assertion / Response 签名
- SLO 基础能力
- AWS / 阿里云对接样例

## Phase 5 CAS

目标：补齐存量系统兼容能力。

重点输出：

- `/cas/login`
- `/cas/logout`
- `/cas/serviceValidate`
- `/cas/p3/serviceValidate`
- SLO 回调

## Phase 6 LDAP

目标：为依赖 LDAP 的系统提供认证和查询兼容层。

重点输出：

- Bind
- User / Group Search
- DN 映射
- JumpServer / Jenkins LDAP 接入验证

## Phase 7 SCIM

目标：提供面向云平台和 SaaS 的用户/组同步能力。

重点输出：

- Users / Groups
- Patch / Filter / Pagination
- 同步任务
- AWS / 阿里云同步验证

## Phase 8 增强

目标：完善安全性、可观测性和统一登出闭环。

重点输出：

- MFA
- Secret 加密
- Backchannel Logout
- 审计增强
- Prometheus / OpenTelemetry

## 推荐验收顺序

1. 先完成后台登录和 RBAC，再推进协议层
2. 先把 OIDC 与 SAML 打通，再做 CAS / LDAP 兼容
3. SCIM 放在协议层稳定之后，避免重复修改用户与组模型
