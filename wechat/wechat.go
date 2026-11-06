package wechat

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

type Config struct {
	AppID        string
	AppSecret    string
	FetchProfile bool
	// HTTPClient supplies the client used for platform requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: token endpoints must not follow redirects.
	HTTPClient *http.Client
}

type Provider struct {
	appID        string
	appSecret    string
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.CodeExchanger = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.AppID, config.AppSecret) {
		return nil, httpx.Failure(goauth.WeChat, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		appID: config.AppID, appSecret: config.AppSecret,
		fetchProfile: config.FetchProfile, http: httpx.New(goauth.WeChat, config.HTTPClient),
	}, nil
}

func (provider *Provider) Exchange(ctx context.Context, code string) (goauth.User, error) {
	if !httpx.Present(code) {
		return goauth.User{}, httpx.Failure(goauth.WeChat, "exchange", goauth.ErrInvalidCredential)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		OpenID      string `json:"openid"`
		UnionID     string `json:"unionid"`
		ExpiresIn   int64  `json:"expires_in"`
		ErrCode     int64  `json:"errcode"`
	}
	var tokenResponse map[string]any
	err := provider.http.JSON(ctx, "exchange", http.MethodGet, "https://api.weixin.qq.com/sns/oauth2/access_token", url.Values{
		"appid": {provider.appID}, "secret": {provider.appSecret},
		"code": {code}, "grant_type": {"authorization_code"},
	}, httpx.Capture(&token, &tokenResponse))
	if token.ErrCode != 0 {
		return goauth.User{}, rejected("exchange", token.ErrCode)
	}
	if err != nil {
		return goauth.User{}, err
	}
	if !httpx.Present(token.AccessToken, token.OpenID) || token.ExpiresIn <= 0 {
		return goauth.User{}, httpx.Failure(goauth.WeChat, "exchange", goauth.ErrResponse)
	}
	user := goauth.User{
		Provider: goauth.WeChat, AppID: provider.appID,
		ID: token.OpenID, SubjectType: goauth.OpenID, UnionID: token.UnionID,
		Raw: make(map[string]any), TokenResponse: tokenResponse,
	}
	if provider.fetchProfile {
		if err := provider.profile(ctx, token.AccessToken, &user); err != nil {
			return goauth.User{}, err
		}
	}
	return user, nil
}

func (provider *Provider) profile(ctx context.Context, accessToken string, user *goauth.User) error {
	var profile struct {
		OpenID     string `json:"openid"`
		UnionID    string `json:"unionid"`
		Nickname   string `json:"nickname"`
		HeadImgURL string `json:"headimgurl"`
		ErrCode    int64  `json:"errcode"`
	}
	var raw map[string]any
	err := provider.http.JSON(ctx, "profile", http.MethodGet, "https://api.weixin.qq.com/sns/userinfo", url.Values{
		"access_token": {accessToken}, "openid": {user.ID}, "lang": {"zh_CN"},
	}, httpx.Capture(&profile, &raw))
	if profile.ErrCode != 0 {
		return rejected("profile", profile.ErrCode)
	}
	if err != nil {
		return err
	}
	if !httpx.Present(profile.OpenID) {
		return httpx.Failure(goauth.WeChat, "profile", goauth.ErrResponse)
	}
	if profile.OpenID != user.ID ||
		(user.UnionID != "" && profile.UnionID != "" && profile.UnionID != user.UnionID) {
		return httpx.Failure(goauth.WeChat, "profile", goauth.ErrIdentityMismatch)
	}
	if profile.UnionID != "" {
		user.UnionID = profile.UnionID
	}
	user.Nickname = profile.Nickname
	user.Avatar = profile.HeadImgURL
	user.Raw = raw
	return nil
}

func rejected(operation string, code int64) error {
	failure := httpx.Rejected(goauth.WeChat, operation, strconv.FormatInt(code, 10))
	switch code {
	case 40003, 40014, 40029, 40163, 42001:
		failure.Kind = goauth.ErrInvalidCredential
	}
	return failure
}
