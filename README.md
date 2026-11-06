# goauth

[![Version](https://img.shields.io/github/v/tag/feymanlee/goauth?label=version)](https://github.com/feymanlee/goauth/tags)
[![Go Version](https://img.shields.io/github/go-mod/go-version/feymanlee/goauth)](https://github.com/feymanlee/goauth/blob/main/go.mod)
[![Go Reference](https://pkg.go.dev/badge/github.com/feymanlee/goauth.svg)](https://pkg.go.dev/github.com/feymanlee/goauth)
[![Standard Library Only](https://img.shields.io/badge/dependencies-standard_library_only-blue)](https://github.com/feymanlee/goauth/blob/main/go.mod)

支持 **微信、QQ、抖音、微博、支付宝** 原生 App 登录的 Go 服务端认证库。验证客户端 SDK 返回的授权凭据，将不同平台的身份和资料统一为 `User`。

**Go 1.22+，仅使用标准库。** 支持同平台多应用配置、可选用户资料、原始响应及令牌信息，提供 `context` 取消与 HTTP 客户端注入。账号绑定和登录态由接入方管理，不绑定 Web 框架、数据库或 JWT 实现。

参考 `picapica/pkg/socialite` 的职责划分重新设计与实现，保留平台适配、统一身份和多应用实例的架构，不依赖其代码。

## 支持范围

客户端通过平台 SDK 获得凭据，经业务后端调用本库验证；认证成功后，由业务后端查找或绑定站内账号并建立登录态。

| 平台 | 服务端入口 | 客户端提交的凭据 | 身份与应用归属 |
| --- | --- | --- | --- |
| 微信 App | `wechat.Provider.Exchange` | SDK 返回的授权码 `code` | 使用配置的 AppID / AppSecret 换码，取可信 OpenID |
| QQ App | `qq.Provider.Verify` | SDK 返回的 `access_token` | `/oauth2.0/me` 返回的 `client_id` 必须匹配 AppID，取可信 OpenID |
| 抖音 App | `douyin.Provider.Exchange` | SDK 返回的授权码 `code` | 使用配置的 ClientKey / ClientSecret 换码，取 `data.open_id` |
| 微博 App | `weibo.Provider.Verify` | SDK 返回的 `access_token` | token info 的 `appkey` 必须匹配 App Key，验证剩余有效期，取 UID |
| 支付宝 App | `alipay.Provider.Exchange` | SDK 返回的 `auth_code` | RSA2 请求签名、支付宝公钥响应验签，取配置类型的身份标识 |

这些入口用于原生 App，不能混入小程序登录 code、应用级 token 或裸 OpenID。客户端报来的用户 ID 不作为认证依据。客户端 SDK 初始化、授权参数准备与登录事务管理由接入方完成。

## 快速接入

安装已发布版本：

```sh
go get github.com/feymanlee/goauth@v0.1.0
```

在当前仓库可直接运行 `go test ./...`；本地联调可在接入项目的 `go.mod` 中通过 `replace` 指向本地检出目录。

```go
provider, err := wechat.New(wechat.Config{
    AppID:     appID,
    AppSecret: appSecret,
})
if err != nil {
    return err
}

user, err := provider.Exchange(ctx, codeFromMobileSDK)
if err != nil {
    return err
}
key := user.Key()
```

这里 `wechat` 的导入路径是 `github.com/feymanlee/goauth/wechat`。将 `key` 作为第三方绑定记录的身份键，业务自行完成站内账号查找、绑定和会话签发。

各平台构造方式：

```go
wechatProvider, err := wechat.New(wechat.Config{
    AppID: appID, AppSecret: appSecret,
})
qqProvider, err := qq.New(qq.Config{
    AppID: appID,
})
douyinProvider, err := douyin.New(douyin.Config{
    ClientKey: clientKey, ClientSecret: clientSecret,
})
weiboProvider, err := weibo.New(weibo.Config{
    AppKey: appKey,
})
alipayProvider, err := alipay.New(alipay.Config{
    AppID:              appID,
    PrivateKeyPEM:      applicationPrivateKeyPEM,
    AlipayPublicKeyPEM: alipayPublicKeyPEM,
})
```

上面的构造语句是独立示意；每次调用都应处理返回的 `err`。所有构造函数返回的实例可重复、并发使用。同平台多应用分别创建实例；实例不会存储用户凭据或认证结果。

### 通用 User

```go
type User struct {
    ID            string         `json:"id"`
    Nickname      string         `json:"nickname"`
    Name          string         `json:"name"`
    Email         string         `json:"email"`
    Avatar        string         `json:"avatar"`
    Raw           map[string]any `json:"raw"`
    TokenResponse map[string]any `json:"token_response"`
    Provider      Provider       `json:"provider"`
    AppID         string         `json:"app_id"`
    SubjectType   SubjectType    `json:"subject_type"`
    UnionID       string         `json:"union_id,omitempty"`
}
```

`Exchange` 和 `Verify` 统一返回 `User`。`ID` 是第三方用户标识，统一使用字符串以容纳 OpenID 与大整数 UID；它不是站内用户 ID。资料平铺在 `Nickname`、`Name`、`Email`、`Avatar` 字段中，平台未提供的字段保持空字符串，不用昵称推断姓名或邮箱。

`User.Key()` 返回可比较的 `IdentityKey`，包含 **平台、应用、标识类型、主体标识** 四个字段。数据库可对四者建立联合唯一约束；不要把裸 `ID`、昵称或头像作为跨平台账号主键。只需要身份时，`user.Identity()` 返回不含用户资料及令牌的 `Identity`，其中 `Subject` 对应 `user.ID`。

微信、QQ、抖音使用 `goauth.OpenID`；微博使用 `goauth.UserID`。支付宝默认要求 `open_id`；存量应用若配置为 `user_id` 模式，构造时显式设置 `SubjectType: goauth.UserID`。缺少所选类型时返回错误，不自动切换身份类型，以免应用升级时悄悄改变账号键。

`UnionID` 只在平台实际返回时填写。它的范围由平台和开发者账号／应用分组决定，不代表全局用户 ID，也不自动触发账号合并。QQ 基础 `/me` 流程不申请额外的 UnionID 权限，因此通常没有此字段；抖音通常需获取资料才能得到它。

### 原始资料与令牌

`Raw` 保留本次成功获取的原始用户资料，包括未映射到通用字段的平台特有字段；它不会混入换码响应。`TokenResponse` 保留令牌上下文，平台实际返回的 `refresh_token`、`scope`、`token_type` 和额外字段都会保留。

| 平台 | `Raw` 来源 | `TokenResponse` 来源 |
| --- | --- | --- |
| 微信 | `/sns/userinfo` 响应 | 换码接口完整 JSON 对象 |
| QQ | `/user/get_user_info` 响应 | `{"access_token": 已验证的输入令牌}` |
| 抖音 | 资料响应的 `data` 对象 | 换码响应的 `data` 对象 |
| 微博 | `/2/users/show.json` 响应 | `{"access_token": 已验证的输入令牌}` |
| 支付宝 | 验签后的资料业务对象 | 验签后的 token 业务对象 |

QQ、微博的服务端流程只接收并验证 SDK 令牌，没有取得客户端换码响应，因此不伪造 `token_type`、`scope` 或刷新令牌。抖音去掉外层协议封装，支付宝去掉外层响应键和签名字段；两者都可直接通过 `user.TokenResponse["access_token"]` 访问令牌。

两张 map 每次调用独立创建。原始 JSON 中的数字以 `json.Number` 保存，重新序列化仍为 JSON 数字，并保留大整数精度；这与规范化的字符串 `User.ID` 区分开来。

### 令牌有效期

各平台都在验证时校验令牌或授权结果的有效期为正数，但有效期的返回形状不同；按 [通用 User 与原始响应](docs/adr/0003-user-and-provider-responses.md) 的决策，`User` 不另设规范化字段，接入方按下表从 `TokenResponse` 读取：

| 平台 | 有效期读取方式 |
| --- | --- |
| 微信 | `user.TokenResponse["expires_in"]`，JSON 数字（`json.Number`） |
| 抖音 | `user.TokenResponse["expires_in"]`，`TokenResponse` 已是换码响应的 `data` 对象 |
| 支付宝 | `user.TokenResponse["expires_in"]`，字符串秒数 |
| QQ | 验证接口不返回有效期，如需判断请另行调用平台接口 |
| 微博 | 验证时已要求剩余秒数 `expire_in > 0`，过期令牌直接返回 `ErrInvalidCredential`；该值不保留在结果中 |

当前平台通常不提供邮箱。微博 `name` 映射到 `Name`；支付宝仅在已有权限且响应实际包含 `user_name`、`email` 时映射它们。姓名字段不等同于实名认证结论，邮箱字段也不表示邮箱已验证。

### 可选用户资料

每个平台配置都有 `FetchProfile`，默认为 `false`：仅验证身份，不额外请求昵称和头像，也不要求额外的资料权限。

设置 `FetchProfile: true` 后，库会继续获取平台允许的资料，校验协议提供的身份／应用字段，再填入 `User` 的平铺资料字段和 `Raw`。资料字段本身允许为空；如果资料请求失败或身份不一致，整个调用返回错误及零值 `User`，不返回部分结果或令牌。若业务不需要资料，保持默认值即可，此时 `raw` 序列化为 `{}`，资料字符串为空，但仍返回认证成功后的 `token_response`。

资料权限需提前在平台配置并由用户授权；调用资料接口不会提升已有权限。授权码可能在资料请求失败之前已被消费，此时不能用同一个 code 重试整个登录流程。

### 能力接口

```go
type CodeExchanger interface {
    Exchange(context.Context, string) (User, error)
}

type TokenVerifier interface {
    Verify(context.Context, string) (User, error)
}
```

微信、抖音、支付宝实现 `CodeExchanger`；QQ、微博实现 `TokenVerifier`。新增平台可以实现其中一个或两个接口，无需修改核心包或注册中心。具体方法只提供已实现的能力。

### 支付宝密钥

首版支持 OpenAPI V2 的 **RSA2 公钥模式**，生产网关固定为 `https://openapi.alipay.com/gateway.do`。

- `PrivateKeyPEM` 是应用私钥，支持 PEM 格式的 PKCS#1 和 PKCS#8。
- `AlipayPublicKeyPEM` 是支付宝公钥，支持 PEM 格式的 PKIX 和 PKCS#1，不能填成应用公钥。
- RSA 密钥至少 2048 位。裸 Base64、加密私钥和证书模式不在首版支持范围内。
- 请求采用 SHA-256 / PKCS#1 v1.5 签名；成功响应必须对原始 JSON 子对象验签，不能通过重新序列化来规避验签失败。
- 拒绝重复顶层字段、正常与错误响应同时出现、缺失签名和错误签名。平台无签名错误响应只会作为失败返回。

支付宝用户资料接口使用 `auth_token`；本库内部处理签名与参数差异。应用从 `user_id` 迁移到 `open_id` 时，接入方需要另行迁移绑定关系。

### HTTP 与错误

所有方法接收 `context.Context`。每个适配器支持 `HTTPClient: *http.Client` 注入，默认每次请求超时 10 秒；传入客户端未设正超时时也采用 10 秒。库复制客户端配置、不修改传入对象，始终禁止 HTTP 重定向，并限制响应正文为 1 MiB。自定义 Transport、代理和 TLS 配置由接入方管理，不应记录含凭据的请求 URL 或正文。

推荐为整个认证过程设置 `context.WithTimeout`，同时约束换码与资料读取。库不自动重试，避免重放一次性授权码。

```go
if errors.Is(err, goauth.ErrInvalidCredential) {
    return askClientToAuthorizeAgain()
}
var failure *goauth.Error
if errors.As(err, &failure) {
    log.Printf("provider=%s operation=%s code=%s http=%d",
        failure.Provider, failure.Operation, failure.Code, failure.StatusCode)
}
```

`askClientToAuthorizeAgain` 代表业务自己的重新授权处理。分类包括：

| 错误 | 含义 |
| --- | --- |
| `ErrInvalidConfig` | 缺少配置、密钥格式或类型不支持 |
| `ErrInvalidCredential` | 空凭据或已识别的失效、过期凭据 |
| `ErrProvider` | 平台拒绝请求，保留受限长度和字符集的错误码 |
| `ErrIdentityMismatch` | 平台返回的应用或用户身份不一致 |
| `ErrSignature` | 支付宝响应缺失签名或验签失败 |
| `ErrResponse` | 非预期 JSON、缺少必要字段、响应过大等 |
| `ErrTransport` | 网络错误、重定向或未解析为平台错误的 HTTP 非成功状态 |

取消和超时可用 `errors.Is(err, context.Canceled)`、`errors.Is(err, context.DeadlineExceeded)` 判断。未识别的平台业务错误返回 `ErrProvider`；错误响应结构无法解析时按响应或 HTTP 错误处理。

`User` 按通用用户模型包含原始资料与令牌信息，JSON 序列化也包含 `token_response`。需要仅保存或传递身份时使用 `user.Identity()`；库不会把请求中的应用密钥、私钥或授权码添加到返回值。错误仍不包含平台错误描述、响应正文及底层带凭据 URL 的错误字符串。本库不记录日志。

## 可运行示例与测试

`examples/login` 提供五个平台共用的命令行示例，从环境变量读取参数：

| 环境变量 | 用途 |
| --- | --- |
| `GOAUTH_APP_ID` | 当前平台的 AppID、ClientKey 或 App Key |
| `GOAUTH_APP_SECRET` | 微信 AppSecret 或抖音 ClientSecret |
| `GOAUTH_CREDENTIAL` | 当前 SDK 返回的 code 或 access token |
| `GOAUTH_ALIPAY_PRIVATE_KEY_FILE` | 支付宝应用私钥 PEM 文件路径 |
| `GOAUTH_ALIPAY_PUBLIC_KEY_FILE` | 支付宝公钥 PEM 文件路径 |

配置所需环境变量后运行：

```sh
go run ./examples/login -provider wechat
go run ./examples/login -provider qq -profile
go run ./examples/login -provider douyin
go run ./examples/login -provider weibo
go run ./examples/login -provider alipay -alipay-subject open_id
```

示例会调用真实平台并可能消费一次性 code，输出完整 `User` JSON（包含令牌）；使用你为对应应用取得的凭据。添加 `-profile` 可同时输出通用资料与 `raw`。普通测试全部使用本地模拟 HTTP 服务，不请求真实平台：

```sh
go test ./...
go test -race ./...
go vet ./...
```

GitLab CI 配置位于 [`.gitlab-ci.yml`](.gitlab-ci.yml)，参考 `go-sms` 的多版本测试策略，覆盖 Go 1.22、1.25、1.26，并在 Go 1.26 上额外执行 race 测试。流水线在 push（含 tag）和 Merge Request 时运行；分支已有 MR 时只运行 MR 流水线，避免重复。使用支持容器镜像的 GitLab Runner，不需要平台登录凭据。

测试覆盖请求协议、身份归属、缺失字段、平台错误、资料不一致、RSA2 签名／验签、HTTP 异常与取消。模拟测试不代替真实应用联调：上线前仍需使用各平台已配置的 App SDK、权限和真实账号验证成功路径。

## 设计与协议依据

- [术语表](GLOSSARY.md)
- [设计记录](docs/design.md)
- [职责边界](docs/adr/0001-authentication-boundary.md)
- [身份作用域与能力接口](docs/adr/0002-identity-scope-and-capabilities.md)
- [通用 User 与原始响应](docs/adr/0003-user-and-provider-responses.md)
- [协议来源与兼容范围](docs/protocols.md)
