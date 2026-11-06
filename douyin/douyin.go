package douyin

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

type Config struct {
	ClientKey    string
	ClientSecret string
	FetchProfile bool
	// HTTPClient supplies the client used for platform requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: token endpoints must not follow redirects.
	HTTPClient *http.Client
}

type Provider struct {
	clientKey    string
	clientSecret string
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.CodeExchanger = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.ClientKey, config.ClientSecret) {
		return nil, httpx.Failure(goauth.Douyin, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		clientKey: config.ClientKey, clientSecret: config.ClientSecret,
		fetchProfile: config.FetchProfile, http: httpx.New(goauth.Douyin, config.HTTPClient),
	}, nil
}

func (provider *Provider) Exchange(ctx context.Context, code string) (goauth.User, error) {
	if !httpx.Present(code) {
		return goauth.User{}, httpx.Failure(goauth.Douyin, "exchange", goauth.ErrInvalidCredential)
	}
	var response struct {
		Data *struct {
			ErrorCode   *httpx.Int64 `json:"error_code"`
			AccessToken string       `json:"access_token"`
			OpenID      string       `json:"open_id"`
			ExpiresIn   int64        `json:"expires_in"`
		} `json:"data"`
	}
	var tokenResponse map[string]any
	err := provider.http.JSON(ctx, "exchange", http.MethodPost, "https://open.douyin.com/oauth/access_token/", url.Values{
		"client_key": {provider.clientKey}, "client_secret": {provider.clientSecret},
		"code": {code}, "grant_type": {"authorization_code"},
	}, httpx.Capture(&response, &tokenResponse))
	if response.Data != nil && response.Data.ErrorCode != nil {
		if code := *response.Data.ErrorCode; code != 0 {
			return goauth.User{}, rejected("exchange", int64(code))
		}
	}
	if err != nil {
		return goauth.User{}, err
	}
	if response.Data == nil || response.Data.ErrorCode == nil {
		return goauth.User{}, httpx.Failure(goauth.Douyin, "exchange", goauth.ErrResponse)
	}
	token := response.Data
	if !httpx.Present(token.AccessToken, token.OpenID) || token.ExpiresIn <= 0 {
		return goauth.User{}, httpx.Failure(goauth.Douyin, "exchange", goauth.ErrResponse)
	}
	tokenData, valid := tokenResponse["data"].(map[string]any)
	if !valid {
		return goauth.User{}, httpx.Failure(goauth.Douyin, "exchange", goauth.ErrResponse)
	}
	user := goauth.User{
		Provider: goauth.Douyin, AppID: provider.clientKey,
		ID: token.OpenID, SubjectType: goauth.OpenID,
		Raw: make(map[string]any), TokenResponse: tokenData,
	}
	if provider.fetchProfile {
		if err := provider.profile(ctx, token.AccessToken, &user); err != nil {
			return goauth.User{}, err
		}
	}
	return user, nil
}

func (provider *Provider) profile(ctx context.Context, accessToken string, user *goauth.User) error {
	var response struct {
		ErrNo *httpx.Int64 `json:"err_no"`
		Data  *struct {
			ErrorCode *httpx.Int64 `json:"error_code"`
			OpenID    string       `json:"open_id"`
			ClientKey string       `json:"client_key"`
			UnionID   string       `json:"union_id"`
			Nickname  string       `json:"nickname"`
			Avatar    string       `json:"avatar"`
		} `json:"data"`
	}
	var raw map[string]any
	err := provider.http.PostJSON(ctx, "profile", "https://open.douyin.com/oauth/userinfo/", map[string]string{
		"access_token": accessToken, "open_id": user.ID,
	}, httpx.Capture(&response, &raw))
	if response.ErrNo != nil && *response.ErrNo != 0 {
		return rejected("profile", int64(*response.ErrNo))
	}
	if response.Data != nil && response.Data.ErrorCode != nil && *response.Data.ErrorCode != 0 {
		return rejected("profile", int64(*response.Data.ErrorCode))
	}
	if err != nil {
		return err
	}
	if response.ErrNo == nil || response.Data == nil {
		return httpx.Failure(goauth.Douyin, "profile", goauth.ErrResponse)
	}
	profile := response.Data
	if !httpx.Present(profile.OpenID, profile.ClientKey) {
		return httpx.Failure(goauth.Douyin, "profile", goauth.ErrResponse)
	}
	if profile.OpenID != user.ID || profile.ClientKey != provider.clientKey {
		return httpx.Failure(goauth.Douyin, "profile", goauth.ErrIdentityMismatch)
	}
	profileData, valid := raw["data"].(map[string]any)
	if !valid {
		return httpx.Failure(goauth.Douyin, "profile", goauth.ErrResponse)
	}
	user.UnionID = profile.UnionID
	user.Nickname = profile.Nickname
	user.Avatar = profile.Avatar
	user.Raw = profileData
	return nil
}

func rejected(operation string, code int64) error {
	failure := httpx.Rejected(goauth.Douyin, operation, strconv.FormatInt(code, 10))
	switch code {
	case 10007, 10008, 28001003, 28001008:
		failure.Kind = goauth.ErrInvalidCredential
	case 10014:
		failure.Kind = goauth.ErrIdentityMismatch
	}
	return failure
}
