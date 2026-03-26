# Alibaba Cloud CloudSSO Example

这个示例用于把 `openauthing` 作为阿里云 CloudSSO 的外部身份源来准备接入材料。

当前示例覆盖两部分：

- SAML 2.0：让 `openauthing` 作为外部 IdP，负责登录认证
- SCIM 2.0：为用户和组同步准备目标系统配置和字段映射

当前仓库里的 SCIM 说明是“配置准备”和“字段契约”级别，不代表 `openauthing` 已经实现了完整的 SCIM 出站同步。

阿里云官方参考：

- [CloudSSO: Configure SSO](https://www.alibabacloud.com/help/doc-detail/265368.html)
- [CloudSSO: GetDirectorySAMLServiceProviderInfo](https://www.alibabacloud.com/help/doc-detail/609417.html)
- [CloudSSO: SetExternalSAMLIdentityProvider](https://www.alibabacloud.com/help/doc-detail/609418.html)
- [CloudSSO: Enable or disable SCIM synchronization](https://www.alibabacloud.com/help/doc-detail/264935.html)
- [CloudSSO: Manage SCIM credentials](https://www.alibabacloud.com/help/en/cloudsso/user-guide/manage-scim-credentials)
- [CloudSSO: SCIM 2.0 operations that are supported by CloudSSO](https://www.alibabacloud.com/help/doc-detail/2504520.html)

## 目录内容

- `docker-compose.yml`：启动 `openauthing + postgres + redis`
- `alicloud-cloudsso.env.example`：需要从 CloudSSO 控制台抄回来的 SAML / SCIM 值
- `seed/alicloud_cloudsso_seed.sql`：写入 CloudSSO 对接需要的 `saml-sp` 应用、`scim-target` 应用、测试用户和测试组
- `scripts/bootstrap.sh`：Linux 下的一键初始化脚本
- `tools/hash_argon2id.go`：生成测试用户密码哈希，避免明文密码入库

## openauthing 在阿里云对接中的定位

- `openauthing` 充当 CloudSSO 的外部 SAML IdP
- CloudSSO 仍然负责：
  - 云账号访问入口
  - 账号与访问配置分配
  - 已同步用户和组的目录承载
- SAML 解决“怎么登录”
- SCIM 解决“用户和组怎么先出现在 CloudSSO 目录里”

如果只有 SAML、没有 SCIM，常见结果是：

- 用户可以跳到 `openauthing` 登录
- 但 CloudSSO 目录里还没有对应用户或组
- 最终无法完成用户分配和访问权限分配

## 先决条件

- Linux shell
- Docker Engine 或 Docker Desktop
- `curl`
- 一套已启用 CloudSSO 的阿里云资源目录

## CloudSSO 中外部 IdP 需要的配置项

按阿里云 CloudSSO 官方文档，手工配置外部 IdP 至少需要这些字段：

- `Entity ID`
- `Logon URL`
- `Certificate`

如果你不想手工输入，也可以上传 `openauthing` 的 IdP metadata。

在 `openauthing` 里，这些值对应为：

- `Entity ID`
  对应 `GET /saml/idp/metadata` 返回的 IdP `entityID`
- `Logon URL`
  对应 `http://YOUR_OPENAUTHING_HOST/saml/idp/sso`
- `Certificate`
  对应 `GET /saml/idp/metadata` 返回的签名证书

可选配置：

- `WantRequestSigned`
  CloudSSO API 支持配置，但当前 `openauthing` 还没有实现 AuthnRequest 签名校验，所以示例里先按 `false` 处理

## SAML metadata / entityID / SSO URL 对应关系

CloudSSO 作为 SP，`openauthing` 作为 IdP。

CloudSSO 侧拿到的 SP 信息和 `openauthing` 的对应关系是：

- CloudSSO `Entity ID`
  对应 `saml_service_providers.entity_id`
- CloudSSO `ACS URL`
  对应 `saml_service_providers.acs_url`
- CloudSSO 如果提供了 `SingleLogoutService`
  再写到 `saml_service_providers.slo_url`
- `openauthing` 的 IdP metadata
  是 `http://YOUR_OPENAUTHING_HOST/saml/idp/metadata`
- `openauthing` 的 IdP SSO URL
  是 `http://YOUR_OPENAUTHING_HOST/saml/idp/sso`

CloudSSO 侧的 SP metadata 可以从控制台查看或通过 `GetDirectorySAMLServiceProviderInfo` 获取。

如果你通过 OpenAPI 拿 SP 信息，重点字段是：

- `EntityId`
- `AcsUrl`
- `EncodedMetadataDocument`
- `AuthnSignAlgo`
- `SupportEncryptedAssertion`

其中 `EncodedMetadataDocument` 是 Base64 编码，Linux 下可以这样落成 XML：

```bash
jq -r '.SAMLServiceProvider.EncodedMetadataDocument' cloudsso-sp.json \
  | base64 -d \
  > ./examples/alicloud-cloudsso/cloudsso-sp-metadata.xml
```

## 推荐属性映射

当前 `openauthing` 的 SAML 属性生成逻辑固定支持内部键：

- `username`
- `email`
- `name`
- `groups`

针对 CloudSSO，推荐输出成下面这些外部属性名：

- `username -> username`
- `email -> email`
- `name -> display_name`
- `groups -> groups`

补充建议：

- `NameID`
  推荐直接使用主邮箱
- `NameID Format`
  推荐 `urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress`
- 如果你的 `username` 不是邮箱，仍然建议让 `NameID` 使用邮箱，便于和 SCIM `userName` 对齐

## 推荐 SCIM 字段映射

阿里云 CloudSSO 的 SCIM 接口文档明确支持 `/Users` 和 `/Groups` 资源。推荐这样映射：

- `userName`
  映射到 `openauthing.users.email`，或一个与 `NameID` 完全一致的唯一登录名
- `displayName`
  映射到 `openauthing.users.display_name`
- `emails`
  映射到主邮箱，建议单值主邮箱
- `active`
  映射到 `openauthing.users.status == active`
- `groups`
  映射到用户所属组

组对象建议：

- `displayName`
  使用稳定、可读的组名
- `externalId`
  放 `openauthing.groups.code` 或固定 UUID
- `members`
  由用户和组关系计算

说明：

- 当前示例只准备 `scim-target` 应用和字段契约，不会真正调用 CloudSSO SCIM API
- `SCIM token` 只保存在本地环境变量文件里，不会写入 `openauthing` 数据库

## SCIM endpoint / SCIM token 的使用方式

按官方文档，CloudSSO 的 SCIM 接入步骤是：

1. 在控制台开启 SCIM 同步
2. 复制 `SCIM Endpoint`
3. 生成 `SCIM Credential`
4. 在同步端使用 `Authorization: Bearer <SCIM token>`

当前示例里的使用方式是：

- `ALICLOUD_CLOUDSSO_SCIM_ENDPOINT`
  保存 CloudSSO 控制台显示的 SCIM endpoint
- `ALICLOUD_CLOUDSSO_SCIM_TOKEN`
  只保存在本地 env 文件，绝不写库

官方限制需要特别注意：

- SCIM credential 只在创建时显示一次
- 如果丢失，必须重新生成并更新同步端配置

## 测试用户和测试组准备

bootstrap 会自动写入：

- 测试用户：
  - `username = cloudsso.demo@example.test`
  - `email = cloudsso.demo@example.test`
  - `display_name = Alibaba Cloud CloudSSO Demo User`
- 测试组：
  - `code = alicloud-platform`
  - `name = Alibaba Cloud Platform`

这样做的目的：

- 让 `SAML NameID`、推荐的 SCIM `userName` 和测试用户邮箱保持一致
- 让组同步和分配访问权限时使用稳定组标识

## 示例配置准备

先复制配置模板：

```bash
cp ./examples/alicloud-cloudsso/alicloud-cloudsso.env.example \
  ./examples/alicloud-cloudsso/alicloud-cloudsso.env
```

把下面这些值填进去：

- `ALICLOUD_CLOUDSSO_SAML_ENTITY_ID`
- `ALICLOUD_CLOUDSSO_SAML_ACS_URL`
- `ALICLOUD_CLOUDSSO_SAML_SLO_URL`，如果当前 CloudSSO 侧没有可用值可以留空
- `ALICLOUD_CLOUDSSO_ACCESS_PORTAL_URL`
- `ALICLOUD_CLOUDSSO_SCIM_ENDPOINT`
- `ALICLOUD_CLOUDSSO_SCIM_TOKEN`

可选值：

- `ALICLOUD_CLOUDSSO_SP_METADATA_XML_PATH`
  如果你从 CloudSSO 控制台或 API 导出了 SP metadata，可以把本地 XML 路径填在这里，bootstrap 会一并写入 `sp_metadata_xml`

## Linux 启动和 seed

```bash
bash ./examples/alicloud-cloudsso/scripts/bootstrap.sh
```

这个脚本会：

1. 启动 `postgres / redis / openauthing`
2. 执行全部 migration
3. 写入一个 `saml-sp` 类型应用
4. 写入一个 `scim-target` 类型应用
5. 写入测试用户和测试组

默认测试数据：

- tenant slug：`alicloud-cloudsso-demo`
- SAML app code：`alicloud-cloudsso-saml`
- SCIM app code：`alicloud-cloudsso-scim`
- demo user：`cloudsso.demo@example.test / Secret123!`
- demo group：`alicloud-platform`

## 在 openauthing 中准备好的示例配置

bootstrap 会准备：

- 一个 `type=saml-sp` 的应用
- 一条 `saml_service_providers` 配置
- 一个 `type=scim-target` 的应用
- 一个测试用户
- 一个测试组和用户组关系

这里的 `scim-target` 应用会保存：

- CloudSSO 的 SCIM endpoint
- 对接目标是阿里云 CloudSSO 这件事实

这里不会保存：

- CloudSSO 的 SCIM token

## 验证流程

1. 登录 CloudSSO 控制台，进入目录设置
2. 配置外部 IdP，查看或复制 CloudSSO 的 `Entity ID` 和 `ACS URL`
3. 把这些值写入本地 `alicloud-cloudsso.env`
4. 执行 `bash ./examples/alicloud-cloudsso/scripts/bootstrap.sh`
5. 访问 `http://localhost:8080/saml/idp/metadata`，确认 `openauthing` 的 IdP metadata 可访问
6. 在 CloudSSO 里选择上传 metadata 文件，或手工填写：
   - `Entity ID`
   - `Logon URL`
   - `Certificate`
7. 在 CloudSSO 里启用 SCIM 同步
8. 记录 CloudSSO 的 `SCIM Endpoint`
9. 生成 SCIM token，并把它只保存到本地 env 文件
10. 按上面的字段映射，把测试用户和测试组同步到 CloudSSO
11. 在 CloudSSO 里把同步进来的用户或组分配到目标访问权限
12. 从 CloudSSO 访问入口发起登录测试
13. 浏览器应跳转到 `openauthing`
14. 用 `cloudsso.demo@example.test / Secret123!` 登录
15. 登录成功后应回到 CloudSSO 访问入口

## 常见问题排查

### metadata 错误

现象：

- CloudSSO 无法保存外部 IdP
- 或者导入 metadata 后登录失败

排查：

- 确认上传的是 `http://YOUR_OPENAUTHING_HOST/saml/idp/metadata`
- 确认 `entityID`、`SingleSignOnService` 和证书都能在 metadata 中找到
- 如果你改过 `OPENAUTHING_SAML_IDP_ENTITY_ID` 或证书文件，重新导出 metadata 再导入

### 证书错误

现象：

- CloudSSO 回调后提示签名验证失败

排查：

- 确认 CloudSSO 里保存的是 `openauthing` 当前实际使用的证书
- 如果 `openauthing` 没显式配置 `OPENAUTHING_SAML_IDP_CERT_FILE / KEY_FILE`，重启后开发证书可能变化
- 生产环境必须使用固定证书和私钥

### SCIM token 配置错误

现象：

- 同步接口返回 `401` 或 `403`
- 同步任务只能创建一部分对象，后续全部失败

排查：

- 确认 `Authorization: Bearer <SCIM token>` 使用的是最新启用的 token
- CloudSSO 官方文档说明 SCIM token 只在创建时显示一次，丢失后需要重新生成
- 如果你做了 token 轮转，先把新 token 切到同步端，再停用旧 token

### 用户组同步不完整

现象：

- 只有用户被同步，组没有同步
- 或者用户存在但没有任何可用访问权限

排查：

- 确认 CloudSSO 已启用 SCIM 同步
- 确认用户和组都被同步，而不是只同步用户
- 确认 `userName` 和 `NameID` 使用同一标识
- 确认组已经在 CloudSSO 中完成访问权限分配

## 当前支持边界

- 当前示例已经达到“工程师可按文档手工准备 CloudSSO 对接信息”的程度
- 当前示例没有自动调用阿里云 API
- 当前示例没有实现 `openauthing` 的 SCIM 出站同步
- 当前示例的 `scim-target` 应用只是对目标系统和字段契约的配置准备
