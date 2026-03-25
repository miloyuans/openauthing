# AWS IAM Identity Center Example

这个示例用于把 `openauthing` 作为 AWS IAM Identity Center 的外部身份源来准备接入材料。

当前示例覆盖两部分：

- SAML 2.0：让 `openauthing` 作为外部 IdP，负责登录认证
- SCIM 2.0：为用户和组同步准备目标系统配置和字段映射

当前仓库里的 SCIM 说明是“配置准备”和“字段契约”级别，不代表 `openauthing` 已经实现了完整的 SCIM 出站同步。

AWS 官方参考：

- [Use IAM Identity Center with an external identity provider](https://docs.aws.amazon.com/singlesignon/latest/userguide/other-idps.html)
- [Connect to an external identity provider](https://docs.aws.amazon.com/singlesignon/latest/userguide/how-to-connect-idp.html)
- [Provision users and groups from an external identity provider using SCIM](https://docs.aws.amazon.com/singlesignon/latest/userguide/provision-automatically.html)
- [Considerations for using automatic provisioning](https://docs.aws.amazon.com/singlesignon/latest/userguide/users-groups-provisioning.html)

## 目录内容

- `docker-compose.yml`：启动 `openauthing + postgres + redis`
- `aws-iam-identity-center.env.example`：需要从 AWS 控制台抄回来的 SAML / SCIM 值
- `seed/aws_iam_identity_center_seed.sql`：写入 AWS 对接需要的 `saml-sp` 应用、`scim-target` 应用、测试用户和测试组
- `scripts/bootstrap.sh`：Linux 下的一键初始化脚本
- `tools/hash_argon2id.go`：生成测试用户密码哈希，避免明文密码入库

## openauthing 在 AWS 对接中的定位

- `openauthing` 充当 AWS IAM Identity Center 的外部 SAML IdP
- IAM Identity Center 仍然负责：
  - AWS 账号分配
  - permission set 分配
  - 已同步用户和组的目录承载
- SAML 解决“怎么登录”
- SCIM 解决“用户和组怎么先出现在 IAM Identity Center 里”

如果只有 SAML、没有 SCIM，常见结果是：

- 用户能跳到 `openauthing` 登录
- 但 IAM Identity Center 里没有对应用户或组
- 最终无法给 AWS 账号分配 permission set

## 先决条件

- Linux shell
- Docker Engine 或 Docker Desktop
- `curl`
- `pwsh` 不是必需项；这个示例的主流程已经用 `bash` 提供
- 一个已启用 AWS IAM Identity Center 的 AWS 账号

## SAML metadata / entityID / SSO URL 对应关系

在 AWS IAM Identity Center 控制台里把身份源切到“外部身份提供商”后，会出现一组 AWS 作为 SP 的元数据。

这些值和 `openauthing` 的对应关系是：

- AWS metadata 里的 `entityID`
  对应 `saml_service_providers.entity_id`
- AWS metadata 里的 `AssertionConsumerService Location`
  对应 `saml_service_providers.acs_url`
- `openauthing` 的 IdP metadata 地址
  是 `http://YOUR_OPENAUTHING_HOST/saml/idp/metadata`
- `openauthing` 的 IdP SSO URL
  是 `http://YOUR_OPENAUTHING_HOST/saml/idp/sso`
- 如果 AWS metadata 里提供了 `SingleLogoutService`
  再把它写到 `saml_service_providers.slo_url`

推荐做法：

1. 在 AWS 控制台下载 AWS IAM Identity Center 的 SP metadata
2. 从 metadata 里提取 `entityID` 和 `ACS URL`
3. 把这些值写进 `aws-iam-identity-center.env`
4. 再运行 `bootstrap.sh`

## AWS 侧需要配置的字段

在 AWS IAM Identity Center 控制台配置外部 IdP 时，至少需要这些值：

- IdP metadata file
  使用 `openauthing` 的 `GET /saml/idp/metadata`
- IdP issuer / entity ID
  对应 `openauthing` 的 SAML IdP `entityID`
- Sign-in URL / SSO URL
  对应 `http://YOUR_OPENAUTHING_HOST/saml/idp/sso`
- Signing certificate
  来自 `openauthing` 的 IdP metadata

openauthing 这一侧至少要保存：

- AWS `entityID`
- AWS `ACS URL`
- 可选的 AWS `SLO URL`
- 推荐的属性映射

## 推荐的 SAML 属性映射

推荐把 AWS IAM Identity Center 的登录主标识和 SCIM `userName` 做到一致。

- `NameID`
  推荐使用用户主邮箱
  格式推荐 `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- `email`
  推荐使用用户主邮箱
- `username`
  推荐也使用与邮箱一致的登录名，便于和 AWS `userName` 对齐
- `groups`
  可以在 SAML Assertion 里带出，但不要把它当成 AWS 账号授权来源；AWS 账号分配还是依赖 SCIM 同步进去的组

实操建议：

- 对 AWS IAM Identity Center，最稳妥的做法是让 `NameID == SCIM userName == email`
- 如果你的 `openauthing` 用户名不是邮箱，建议专门为 AWS 场景把 `NameID` 仍然映射到邮箱

## 推荐的 SCIM schema 映射

推荐映射：

- `userName`
  `openauthing.users.email` 或者一个与 `NameID` 完全一致的唯一登录名
- `displayName`
  `openauthing.users.display_name`
- `emails`
  主邮箱，建议单值主邮箱
- `active`
  `openauthing.users.status == active`
- `groups`
  来自 `openauthing` 的组列表；建议组 `displayName` 稳定且唯一

额外建议：

- 组同步时把稳定标识放到 `externalId`
- 组的 `displayName` 用对 AWS 管理员可读的名字
- 不要依赖嵌套组；AWS IAM Identity Center 的自动预配场景对组结构有约束

## 示例配置准备

先复制配置模板：

```bash
cp ./examples/aws-iam-identity-center/aws-iam-identity-center.env.example \
  ./examples/aws-iam-identity-center/aws-iam-identity-center.env
```

把下面这些值填进去：

- `AWS_IIC_SAML_ENTITY_ID`
- `AWS_IIC_SAML_ACS_URL`
- `AWS_IIC_SAML_SLO_URL`，如果 AWS metadata 没给可以留空
- `AWS_IIC_ACCESS_PORTAL_URL`
- `AWS_IIC_SCIM_ENDPOINT`
- `AWS_IIC_SCIM_ACCESS_TOKEN`

说明：

- `AWS_IIC_SCIM_ACCESS_TOKEN` 只保存在本地 env 文件里，不会写进 openauthing 数据库
- `scim-target` 应用只是当前仓库里对目标系统的配置占位，真正的 SCIM 出站同步能力还没有在本任务里实现

## Linux 启动和 seed

```bash
bash ./examples/aws-iam-identity-center/scripts/bootstrap.sh
```

这个脚本会：

1. 启动 `postgres / redis / openauthing`
2. 执行全部 migration
3. 写入一个 `saml-sp` 类型应用
4. 写入一个 `scim-target` 类型应用
5. 写入测试用户和测试组

默认测试数据：

- tenant slug：`aws-iam-identity-center-demo`
- SAML app code：`aws-iam-identity-center-saml`
- SCIM app code：`aws-iam-identity-center-scim`
- demo user：`aws.demo@example.test / Secret123!`
- demo group：`aws-engineering`

## 在 openauthing 中准备好的示例配置

bootstrap 会准备：

- 一个 `type=saml-sp` 的应用
- 一条 `saml_service_providers` 配置
- 一个 `type=scim-target` 的应用
- 一个测试用户
- 一个测试组和用户组关系

这里的 `scim-target` 应用会保存：

- AWS IAM Identity Center 的 SCIM endpoint
- 对接目标是 AWS IAM Identity Center 这一事实

这里不会保存：

- AWS 的 SCIM bearer token

## 验证流程

1. 在 AWS IAM Identity Center 控制台切换到外部 IdP
2. 下载 AWS 的 SP metadata
3. 把 AWS metadata 里的 `entityID`、`ACS URL` 填到本地 env 文件
4. 运行 `bootstrap.sh`
5. 用浏览器访问 `http://localhost:8080/saml/idp/metadata`，确认 `openauthing` IdP metadata 可访问
6. 在 AWS 控制台上传或填写 `openauthing` 的 IdP metadata / issuer / SSO URL
7. 在 AWS 控制台开启 SCIM 自动预配，记下 `SCIM endpoint` 和 `access token`
8. 把 `SCIM endpoint` 填到本地 env 文件；`access token` 只保存在本地，不入库
9. 按 README 的映射建议，把测试用户和测试组同步到 IAM Identity Center
10. 在 AWS 中把同步进来的用户或组分配到目标 AWS 账号和 permission set
11. 从 AWS access portal 或 IAM Identity Center 发起登录测试
12. 浏览器应跳转到 `openauthing`
13. 用 `aws.demo@example.test / Secret123!` 登录
14. 登录成功后应回到 AWS access portal

## 测试用户和测试组准备步骤

示例里的默认准备方式是 bootstrap 自动写入：

- 测试用户：
  - `username = aws.demo@example.test`
  - `email = aws.demo@example.test`
  - `display_name = AWS IAM Identity Center Demo User`
- 测试组：
  - `code = aws-engineering`
  - `name = AWS Engineering`

为什么这里把 `username` 和 `email` 做成一致：

- 这样更容易让 SAML `NameID`、SCIM `userName` 和 AWS 侧已预配用户对齐

## 常见错误排查

### SAML issuer 不匹配

现象：

- AWS 提示外部 IdP 配置无效
- 或登录后 SAML 验证失败

排查：

- 确认 AWS 配置的 IdP metadata 来自 `http://YOUR_OPENAUTHING_HOST/saml/idp/metadata`
- 确认 `openauthing` 的 IdP `entityID` 与 metadata 中一致
- 确认 AWS metadata 里的 `entityID` 被正确写入 `saml_service_providers.entity_id`

### ACS 配置错误

现象：

- 登录后回不到 AWS
- `openauthing` 日志提示 `ACS URL does not match`

排查：

- 以 AWS 下载的 SP metadata 为准
- 不要手写猜测 ACS URL
- 每次 AWS identity source 配置变更后，重新核对 metadata

### 用户未 provision

现象：

- 成功完成 SAML 登录，但 AWS access portal 里没有可访问账号
- 或 IAM Identity Center 找不到对应用户

排查：

- 确认该用户已经通过 SCIM 预配进 IAM Identity Center
- 确认 `SCIM userName` 与 `SAML NameID` 使用的是同一个标识
- 确认用户在 IAM Identity Center 中仍是 active

### 组未分配 permission set

现象：

- 用户存在，也能登录，但没有任何 AWS 账号可选

排查：

- 确认组已经通过 SCIM 同步进 IAM Identity Center
- 确认这个组已经被分配到目标 AWS 账号
- 确认这个组已经绑定了 permission set

## 当前支持边界

- 当前示例已经达到“工程师可按文档手工准备 AWS 对接信息”的程度
- 当前示例没有自动调用 AWS API
- 当前示例没有实现 openauthing 的 SCIM 出站同步
- 当前示例的 `scim-target` 应用只是对目标系统和映射契约的配置准备
