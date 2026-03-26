# Mock SAML SP Example

这个示例提供一个最小可运行的 Mock SAML SP，用来在本地验证 `openauthing` 的 SAML 主链路，不依赖 AWS、阿里云或其他真实 SP。

这个 Mock SP 支持：

- 生成 `AuthnRequest`
- 以 ACS 端点接收 `SAMLResponse`
- 展示解析后的 `NameID`
- 展示 Assertion `Attributes`
- 展示 `RelayState`
- 基于 `openauthing` IdP metadata 中的证书做最小 XML Signature 验证

当前验证重点是本地联调和 Assertion 结构检查，不追求生产级 SP 功能完整性。

## 目录内容

- `docker-compose.yml`：启动 `openauthing + mock-saml-sp + postgres + redis`
- `mock-saml-sp.env.example`：本地联调环境变量模板
- `scripts/bootstrap.sh`：Linux 下的一键启动、migration 和 seed 脚本
- `seed/mock_saml_sp_seed.sql`：创建 `saml-sp` 应用、SAML SP 配置、测试用户和测试组
- `tools/hash_argon2id.go`：运行时生成 demo 用户密码哈希
- `main.go`、`server.go`：Mock SP 最小服务

## 先决条件

- Linux shell
- Docker Engine 或 Docker Desktop
- `curl`

## Mock SP 设计说明

Mock SP 暴露这些端点：

- `GET /`
  本地操作页，提供一键发起 `AuthnRequest` 的表单
- `GET /login`
  生成 HTTP-Redirect binding 的 `AuthnRequest`，再跳转到 `openauthing /saml/idp/sso`
- `POST /acs`
  接收 `openauthing` 返回的 ACS POST，解析并展示 `Assertion`
- `GET /metadata`
  返回这个 Mock SP 自己的最小 metadata，便于核对 `entityID / ACS / SLO`
- `GET /healthz`
  健康检查

Mock SP 当前展示的关键字段：

- `NameID`
- `NameID Format`
- `SessionIndex`
- `Response Destination`
- `InResponseTo`
- `Response Issuer`
- `Assertion Issuer`
- `RelayState`
- `Attributes`
- `Signature validation`
- 原始解码后的 `SAMLResponse XML`
- 提取出的 `Assertion XML`

Signature 验证策略说明：

- Mock SP 会去抓 `MOCK_SAML_SP_IDP_METADATA_URL`
- 从 metadata 里提取 `X509Certificate`
- 如果 `Response` 或 `Assertion` 上存在 `ds:Signature`，就做最小 XML Signature 验证
- 当前优先用于开发调试，不包含完整的证书信任链和吊销处理

## 环境变量

先复制模板：

```bash
cp ./examples/mock-saml-sp/mock-saml-sp.env.example \
  ./examples/mock-saml-sp/mock-saml-sp.env
```

关键变量：

- `OPENAUTHING_OIDC_ISSUER`
  供 `openauthing` 生成外部可访问的 SAML IdP URL
- `OPENAUTHING_SAML_IDP_ENTITY_ID`
  `openauthing` IdP metadata 的外部 `entityID`
- `MOCK_SAML_SP_BASE_URL`
  浏览器访问 Mock SP 的地址，默认 `http://localhost:8082`
- `MOCK_SAML_SP_ENTITY_ID`
  注册到 `openauthing` 的 SP `entityID`
- `MOCK_SAML_SP_ACS_URL`
  Mock SP ACS 地址
- `MOCK_SAML_SP_IDP_SSO_URL`
  浏览器跳转到 `openauthing` 的 SSO 入口
- `MOCK_SAML_SP_IDP_METADATA_URL`
  Mock SP 服务端用于拉取证书和验证签名的 metadata 地址
- `MOCK_SAML_SP_IDP_METADATA_BROWSER_URL`
  页面里展示给开发者点击查看的 metadata 地址

说明：

- 在 Docker Compose 联调里，浏览器访问的 IdP URL 走 `localhost`
- Mock SP 服务端去拉 metadata 时，默认走容器网络里的 `http://openauthing:8080/...`

## Linux 启动命令

```bash
bash ./examples/mock-saml-sp/scripts/bootstrap.sh
```

这个脚本会：

1. 启动 `postgres / redis / openauthing / mock-saml-sp`
2. 执行全部 migration
3. 生成 demo 用户 Argon2id 密码哈希
4. 抓取 Mock SP metadata
5. 在 `openauthing` 里写入一个 `type=saml-sp` 的应用和 SAML SP 配置
6. 写入 demo 用户、demo 组和用户组关系

默认联调信息：

- openauthing: `http://localhost:8080`
- mock SP: `http://localhost:8082`
- app code: `mock-saml-sp`
- demo user: `mocksaml.demo@example.test / Secret123!`
- demo group: `mock-saml-platform`

## openauthing 中准备好的示例配置

bootstrap 会写入：

- 一个 `type=saml-sp` 的应用
- 一条 `saml_service_providers` 配置
- `entity_id = http://localhost:8082/metadata`
- `acs_url = http://localhost:8082/acs`
- `slo_url = http://localhost:8082/slo`
- `attribute_mapping = {"username":"username","email":"email","name":"display_name","groups":"groups"}`

这样做的目的是：

- 让 Mock SP 收到的 Assertion 直接显示 `display_name`
- 让本地联调能一眼看清属性映射是否正确

## 与 openauthing 的联调步骤

### SP-Initiated SSO

1. 执行 `bash ./examples/mock-saml-sp/scripts/bootstrap.sh`
2. 打开 `http://localhost:8082`
3. 保持默认 `RelayState`，或自己填一个值
4. 选择想测试的 `NameID Format`
5. 点击 `Generate AuthnRequest and Redirect`
6. 浏览器会跳到 `http://localhost:8080/saml/idp/sso`
7. 如果当前没有中心 session，会先进入 `openauthing` 的本地登录页
8. 使用 demo 用户登录：
   - `mocksaml.demo@example.test`
   - `Secret123!`
9. 登录成功后，`openauthing` 会把 `SAMLResponse` POST 回 `http://localhost:8082/acs`
10. 在 Mock SP ACS 页面检查：
   - `NameID`
   - `display_name`
   - `groups`
   - `RelayState`
   - `signature validation`
   - 原始 `Assertion XML`

### IdP-Initiated SSO

如果你想直接从 `openauthing` 发起：

1. 先在浏览器里完成一次本地登录
2. 访问：

```bash
xdg-open "http://localhost:8080/saml/idp/login?app_id=9c000000-0000-0000-0000-000000000001"
```

3. 浏览器会直接拿到回 ACS 的 `SAMLResponse`
4. 再在 Mock SP 页面检查 Assertion 内容

如果你的 Linux 环境没有 `xdg-open`，直接把 URL 粘到浏览器里即可。

## 验收步骤

1. 跑 `bash ./examples/mock-saml-sp/scripts/bootstrap.sh`
2. 打开 `http://localhost:8082`
3. 发起一次 SP-Initiated SSO
4. 确认浏览器最终落到 `/acs`
5. 确认页面里能看到：
   - `NameID`
   - `display_name`
   - `groups`
   - `RelayState`
   - `signature valid`
6. 打开 `http://localhost:8082/metadata`，确认能看到 SP metadata
7. 执行 `make test`

## 故障排查

### ACS URL does not match

现象：

- `openauthing` 返回 `authn request ACS URL does not match the registered service provider ACS URL`

排查：

- 确认 `MOCK_SAML_SP_ACS_URL` 和 seed 进数据库的 `acs_url` 一致
- 确认浏览器访问的 Mock SP 端口就是 `8082`
- 不要在浏览器里手工改 `AuthnRequest` 里的 ACS URL

### unknown service provider issuer

现象：

- `openauthing` 返回 `unknown service provider issuer`

排查：

- 确认 `MOCK_SAML_SP_ENTITY_ID` 和数据库里的 `entity_id` 一致
- 确认你启动的是当前这个示例的 bootstrap，而不是别的 examples

### signature validation skipped

现象：

- ACS 页面显示 `verification skipped`

排查：

- 确认 `MOCK_SAML_SP_IDP_METADATA_URL` 在 Mock SP 容器里可访问
- Compose 联调时默认应该是 `http://openauthing:8080/saml/idp/metadata`
- 如果你改成主机直跑 Mock SP，需要把它改成 `http://localhost:8080/saml/idp/metadata`

### signature validation failed

现象：

- ACS 页面显示 `signature invalid`

排查：

- 确认 `openauthing` 当前启用了固定 SAML 证书，或至少在一次联调会话中没有重启导致开发证书变化
- 确认拉取到的 metadata 是当前运行实例的 metadata
- 当前版本默认验证 `Response` 或 `Assertion` 上存在的签名；如果你后续改了签名策略，需要一起核对 Mock SP 配置

### attributes missing or mapping wrong

现象：

- ACS 页面里 `display_name` 或 `groups` 不存在

排查：

- 确认 `saml_service_providers.attribute_mapping_jsonb` 里用了：
  `{"username":"username","email":"email","name":"display_name","groups":"groups"}`
- 确认 demo 用户已经绑定了 demo 组

## 当前支持边界

- 当前 Mock SP 重点是帮助本地验证 `SAMLResponse / Assertion` 结构
- 当前不实现生产级 SP 会话管理
- 当前不实现完整的 SLO 消费和多会话跟踪
- 当前 Signature 验证是开发调试级别，不等同于生产级证书策略
