# 协议来源与兼容范围

核实日期：2026-11-06。接口行为依据官方文档与官方 SDK；本项目自动化测试通过本地模拟服务验证协议实现，不代表已使用真实应用凭据完成生产联调。

错误处理遵循统一优先级：HTTP 非成功状态的正文若能解码出平台错误码，按平台错误分类（只保留安全错误码，不传播可能含凭据的平台错误描述）；无法解析为平台错误时才按 HTTP 传输错误处理。正文为 JSON 对象时即使状态失败也先解码供错误码判定。

## 微信 App

来源：[微信登录授权后接口调用](https://developers.weixin.qq.com/doc/oplatform/Mobile_App/WeChat_Login/Authorized_API_call_UnionID.html)。

- `GET https://api.weixin.qq.com/sns/oauth2/access_token`：使用 `appid`、`secret`、`code`、`grant_type=authorization_code`。
- `GET https://api.weixin.qq.com/sns/userinfo`：使用换码得到的 `access_token`、`openid`。
- 换码成功必须有访问令牌、OpenID 与正的有效期；存在非零 `errcode` 时拒绝。
- 资料响应的 OpenID 必须一致；两次响应都提供 UnionID 时也必须一致。UnionID 限于同一微信开放平台账号下的应用集合。

## QQ App

来源：[OpenID](https://wiki.connect.qq.com/获取用户openid_oauth2-0/)、[用户资料](https://wiki.connect.qq.com/get_user_info/)、[公共返回码](https://wiki.connect.qq.com/公共返回码说明/)。

- `GET https://graph.qq.com/oauth2.0/me`：传 `access_token` 与 `fmt=json`；检查 `client_id` 等于配置的 AppID，从响应取得 `openid`。
- `GET https://graph.qq.com/user/get_user_info`：传 `access_token`、`oauth_consumer_key`、可信 `openid`。
- 固定请求 JSON，不接受历史 JSONP 包装作为成功结果。资料接口必须显式返回 `ret=0`；正数和负数错误码都拒绝。
- `figureurl_qq_2` 缺省时回退到 `figureurl_qq_1`。基础身份验证不请求需要额外权限的 `unionid=1`。

## 抖音 App

来源：[移动 SDK 获取授权令牌](https://developer.open-douyin.com/docs/resource/zh-CN/dop/develop/sdk/mobile-app/permission/get-permission-token)、[换取访问令牌](https://developer.open-douyin.com/docs/resource/zh-CN/dop/develop/openapi/account-permission/get-access-token)、[获取公开资料](https://developer.open-douyin.com/docs/resource/zh-CN/dop/develop/openapi/account-permission/get-account-open-info)、[官方 Go SDK 固定版本](https://github.com/bytedance/douyin-openapi-sdk-go/blob/a50593c5ccdc31ab5b7cb2153947dfad612bbed9/client/client.go)。

- `POST https://open.douyin.com/oauth/access_token/` 使用表单编码：`client_key`、`client_secret`、`code`、`grant_type=authorization_code`。
- 换码字段位于 `data` 中，要求显式的 `error_code=0`、有效访问令牌、OpenID 及有效期。
- `POST https://open.douyin.com/oauth/userinfo/` 使用 JSON 正文包含 `access_token`、`open_id`，依据当前文档参数表及官方 SDK。文档中的旧 curl 示例仍使用表单，本库采用现行 JSON 形态。
- 资料接口要求顶层 `err_no=0`；内层 `error_code` 若存在也必须为零，兼容字符串和数字。不能要求内外错误码数值相同。
- 资料中的 `open_id` 必须匹配换码结果，`client_key` 必须匹配配置；旧响应若缺少当前成功判定字段会失败，不做猜测式兼容。
- 获取资料需 `user_info` 权限。原生 App 授权码不等于小程序登录码。

## 微博 App

来源：[token 信息](https://open.weibo.com/wiki/Oauth2/get_token_info)、[用户资料](https://open.weibo.com/wiki/2/users/show)、[错误格式](https://open.weibo.com/wiki/Error_code)、[授权机制](https://open.weibo.com/wiki/授权机制)。

- `POST https://api.weibo.com/oauth2/get_token_info` 使用表单 `access_token`，无 `.json` 后缀。
- 检查 `appkey` 等于配置值，使用可信 `uid`，并要求剩余秒数 `expire_in > 0`。
- 文档表格与示例的字段类型不同；UID、App Key、到期时间以及错误码兼容字符串和整数，UID 不经过浮点数转换。
- `expire_in` 是剩余时间，不应与 `create_at` 相加；负数表示已过期。
- `GET https://api.weibo.com/2/users/show.json` 使用可信 UID 查询资料，并核对响应 `id`／`idstr`。
- 非成功 HTTP 响应也可能携带平台错误码；只提取安全错误码，不传播可能含 access token 的平台错误描述。

## 支付宝 App

来源：[服务端接入](https://opendocs.alipay.com/open/218/01epuj)、[换取 token](https://opendocs.alipay.com/open/02ailc)、[RSA2 签名](https://opendocs.alipay.com/common/02khjm)、[用户资料](https://opendocs.alipay.com/open/01834fa5_alipay.user.info.share?scene=common)、[OpenID 说明](https://opendocs.alipay.com/mini/0ai2i6)、[官方 Java SDK 固定版本](https://github.com/alipay/alipay-sdk-java-all/tree/02177d34fce069f6c20d83c13f963150bb45467b/v2)。

- 使用 V2 生产网关 `https://openapi.alipay.com/gateway.do`；公共参数和业务参数以表单提交，签名覆盖全部非空参数（排除 `sign`，包含 `sign_type`）。
- `alipay.system.oauth.token` 使用平铺的 `grant_type=authorization_code` 与 `code`，不包装进 `biz_content`。
- `alipay.user.info.share` 使用 `auth_token`，参与签名，无额外业务参数。
- 参数名排序后使用未 URL 编码的原始值拼接签名原文；签名完成后才做表单编码。时间戳使用 UTC+8。
- token 成功响应允许缺少 `code` 字段；若存在则必须是 `10000`。成功仍要求签名、访问令牌、正的有效期和所选类型的身份标识。资料响应要求 `code=10000`。
- 使用 `json.RawMessage` 保存并验证业务子对象原始字节，不重新序列化、不执行转义斜杠的兼容回退。
- 默认要求应用级 `open_id`；存量 `user_id` 模式需显式配置，避免静默改变身份键。
- 首版支持 RSA2 公钥模式、有限期用户 token；证书模式、V3、令牌刷新与服务商代调用不在实现范围内。
