package qq

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
	FetchProfile bool
	HTTPClient   *http.Client
}

type Provider struct {
	appID        string
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.TokenVerifier = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.AppID) {
		return nil, httpx.Failure(goauth.QQ, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		appID: config.AppID, fetchProfile: config.FetchProfile,
		http: httpx.New(goauth.QQ, config.HTTPClient),
	}, nil
}

func (provider *Provider) Verify(ctx context.Context, accessToken string) (goauth.User, error) {
	if !httpx.Present(accessToken) {
		return goauth.User{}, httpx.Failure(goauth.QQ, "verify", goauth.ErrInvalidCredential)
	}
	var result struct {
		AppID   httpx.Identifier `json:"client_id"`
		OpenID  string           `json:"openid"`
		UnionID string           `json:"unionid"`
		Error   int64            `json:"error"`
	}
	err := provider.http.JSON(ctx, "verify", http.MethodGet, "https://graph.qq.com/oauth2.0/me", url.Values{
		"access_token": {accessToken}, "fmt": {"json"},
	}, &result)
	if err != nil {
		return goauth.User{}, err
	}
	if result.Error != 0 {
		failure := httpx.Rejected(goauth.QQ, "verify", strconv.FormatInt(result.Error, 10))
		switch result.Error {
		case 100013, 100014, 100015, 100016:
			failure.Kind = goauth.ErrInvalidCredential
		}
		return goauth.User{}, failure
	}
	if !httpx.Present(string(result.AppID), result.OpenID) {
		return goauth.User{}, httpx.Failure(goauth.QQ, "verify", goauth.ErrResponse)
	}
	if string(result.AppID) != provider.appID {
		return goauth.User{}, httpx.Failure(goauth.QQ, "verify", goauth.ErrIdentityMismatch)
	}
	user := goauth.User{
		Provider: goauth.QQ, AppID: provider.appID,
		ID: result.OpenID, SubjectType: goauth.OpenID, UnionID: result.UnionID,
		Raw: make(map[string]any), TokenResponse: map[string]any{"access_token": accessToken},
	}
	if provider.fetchProfile {
		if err := provider.profile(ctx, accessToken, &user); err != nil {
			return goauth.User{}, err
		}
	}
	return user, nil
}

func (provider *Provider) profile(ctx context.Context, accessToken string, user *goauth.User) error {
	var profile struct {
		Ret       *int64 `json:"ret"`
		Nickname  string `json:"nickname"`
		AvatarURL string `json:"figureurl_qq_2"`
		Avatar    string `json:"figureurl_qq_1"`
	}
	var raw map[string]any
	err := provider.http.JSON(ctx, "profile", http.MethodGet, "https://graph.qq.com/user/get_user_info", url.Values{
		"access_token": {accessToken}, "oauth_consumer_key": {provider.appID},
		"openid": {user.ID}, "format": {"json"},
	}, httpx.Capture(&profile, &raw))
	if err != nil {
		return err
	}
	if profile.Ret == nil {
		return httpx.Failure(goauth.QQ, "profile", goauth.ErrResponse)
	}
	if *profile.Ret != 0 {
		return httpx.Rejected(goauth.QQ, "profile", strconv.FormatInt(*profile.Ret, 10))
	}
	if profile.AvatarURL == "" {
		profile.AvatarURL = profile.Avatar
	}
	user.Nickname = profile.Nickname
	user.Avatar = profile.AvatarURL
	user.Raw = raw
	return nil
}
