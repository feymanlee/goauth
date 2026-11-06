package weibo

import (
	"context"
	"net/http"
	"net/url"
	"strconv"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

type Config struct {
	AppKey       string
	FetchProfile bool
	// HTTPClient supplies the client used for platform requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: token endpoints must not follow redirects.
	HTTPClient *http.Client
}

type Provider struct {
	appKey       string
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.TokenVerifier = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.AppKey) {
		return nil, httpx.Failure(goauth.Weibo, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		appKey: config.AppKey, fetchProfile: config.FetchProfile,
		http: httpx.New(goauth.Weibo, config.HTTPClient),
	}, nil
}

func (provider *Provider) Verify(ctx context.Context, accessToken string) (goauth.User, error) {
	if !httpx.Present(accessToken) {
		return goauth.User{}, httpx.Failure(goauth.Weibo, "verify", goauth.ErrInvalidCredential)
	}
	var result struct {
		UID       httpx.Identifier `json:"uid"`
		AppKey    httpx.Identifier `json:"appkey"`
		ExpireIn  *httpx.Int64     `json:"expire_in"`
		ErrorCode httpx.Int64      `json:"error_code"`
	}
	err := provider.http.JSON(ctx, "verify", http.MethodPost, "https://api.weibo.com/oauth2/get_token_info", url.Values{
		"access_token": {accessToken},
	}, &result)
	if result.ErrorCode != 0 {
		return goauth.User{}, rejected("verify", int64(result.ErrorCode))
	}
	if err != nil {
		return goauth.User{}, err
	}
	if !httpx.Present(string(result.UID), string(result.AppKey)) || result.UID == "0" || result.ExpireIn == nil {
		return goauth.User{}, httpx.Failure(goauth.Weibo, "verify", goauth.ErrResponse)
	}
	if string(result.AppKey) != provider.appKey {
		return goauth.User{}, httpx.Failure(goauth.Weibo, "verify", goauth.ErrIdentityMismatch)
	}
	if *result.ExpireIn <= 0 {
		return goauth.User{}, httpx.Failure(goauth.Weibo, "verify", goauth.ErrInvalidCredential)
	}
	user := goauth.User{
		Provider: goauth.Weibo, AppID: provider.appKey,
		ID: string(result.UID), SubjectType: goauth.UserID,
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
		ID        httpx.Identifier `json:"id"`
		IDStr     string           `json:"idstr"`
		Nickname  string           `json:"screen_name"`
		Name      string           `json:"name"`
		AvatarURL string           `json:"avatar_large"`
		ImageURL  string           `json:"profile_image_url"`
		ErrorCode httpx.Int64      `json:"error_code"`
	}
	var raw map[string]any
	err := provider.http.JSON(ctx, "profile", http.MethodGet, "https://api.weibo.com/2/users/show.json", url.Values{
		"access_token": {accessToken}, "uid": {user.ID},
	}, httpx.Capture(&profile, &raw))
	if profile.ErrorCode != 0 {
		return rejected("profile", int64(profile.ErrorCode))
	}
	if err != nil {
		return err
	}
	if !httpx.Present(profile.IDStr) && !httpx.Present(string(profile.ID)) {
		return httpx.Failure(goauth.Weibo, "profile", goauth.ErrResponse)
	}
	if (profile.IDStr != "" && profile.IDStr != user.ID) ||
		(profile.ID != "" && string(profile.ID) != user.ID) {
		return httpx.Failure(goauth.Weibo, "profile", goauth.ErrIdentityMismatch)
	}
	if profile.AvatarURL == "" {
		profile.AvatarURL = profile.ImageURL
	}
	user.Nickname = profile.Nickname
	user.Name = profile.Name
	user.Avatar = profile.AvatarURL
	user.Raw = raw
	return nil
}

func rejected(operation string, code int64) error {
	failure := httpx.Rejected(goauth.Weibo, operation, strconv.FormatInt(code, 10))
	switch code {
	case 21314, 21315, 21316, 21317, 21327, 21332:
		failure.Kind = goauth.ErrInvalidCredential
	}
	return failure
}
