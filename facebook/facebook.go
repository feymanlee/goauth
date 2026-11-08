package facebook

import (
	"context"
	"net/http"
	"net/url"
	"strconv"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

const graphAPIVersion = "v27.0"

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

var _ goauth.TokenVerifier = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.AppID, config.AppSecret) {
		return nil, httpx.Failure(goauth.Facebook, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		appID: config.AppID, appSecret: config.AppSecret,
		fetchProfile: config.FetchProfile, http: httpx.New(goauth.Facebook, config.HTTPClient),
	}, nil
}

func (provider *Provider) Verify(ctx context.Context, accessToken string) (goauth.User, error) {
	if !httpx.Present(accessToken) {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrInvalidCredential)
	}
	var result struct {
		Error *struct {
			Code int64 `json:"code"`
		} `json:"error"`
		Data *struct {
			AppID     string `json:"app_id"`
			UserID    string `json:"user_id"`
			IsValid   bool   `json:"is_valid"`
			ExpiresAt int64  `json:"expires_at"`
		} `json:"data"`
	}
	err := provider.http.JSON(ctx, "verify", http.MethodGet, "https://graph.facebook.com/"+graphAPIVersion+"/debug_token", url.Values{
		"input_token":  {accessToken},
		"access_token": {provider.appID + "|" + provider.appSecret},
	}, &result)
	if result.Error != nil && result.Error.Code != 0 {
		return goauth.User{}, rejected("verify", result.Error.Code)
	}
	if err != nil {
		return goauth.User{}, err
	}
	if result.Data == nil {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrResponse)
	}
	if !result.Data.IsValid {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrInvalidCredential)
	}
	if result.Data.AppID != provider.appID {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrIdentityMismatch)
	}
	if !httpx.Present(result.Data.UserID) {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrResponse)
	}
	if result.Data.ExpiresAt != 0 && result.Data.ExpiresAt <= time.Now().Unix() {
		return goauth.User{}, httpx.Failure(goauth.Facebook, "verify", goauth.ErrInvalidCredential)
	}
	user := goauth.User{
		Provider: goauth.Facebook, AppID: provider.appID,
		ID: result.Data.UserID, SubjectType: goauth.UserID,
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
		ID      string `json:"id"`
		Name    string `json:"name"`
		Email   string `json:"email"`
		Picture *struct {
			Data struct {
				URL string `json:"url"`
			} `json:"data"`
		} `json:"picture"`
		Error *struct {
			Code int64 `json:"code"`
		} `json:"error"`
	}
	var raw map[string]any
	err := provider.http.JSON(ctx, "profile", http.MethodGet, "https://graph.facebook.com/"+graphAPIVersion+"/me", url.Values{
		"fields":       {"id,name,email,picture.type(large)"},
		"access_token": {accessToken},
	}, httpx.Capture(&profile, &raw))
	if profile.Error != nil && profile.Error.Code != 0 {
		return rejected("profile", profile.Error.Code)
	}
	if err != nil {
		return err
	}
	if !httpx.Present(profile.ID) {
		return httpx.Failure(goauth.Facebook, "profile", goauth.ErrResponse)
	}
	if profile.ID != user.ID {
		return httpx.Failure(goauth.Facebook, "profile", goauth.ErrIdentityMismatch)
	}
	user.Name = profile.Name
	user.Email = profile.Email
	if profile.Picture != nil {
		user.Avatar = profile.Picture.Data.URL
	}
	user.Raw = raw
	return nil
}

func rejected(operation string, code int64) error {
	failure := httpx.Rejected(goauth.Facebook, operation, strconv.FormatInt(code, 10))
	switch code {
	case 190:
		failure.Kind = goauth.ErrInvalidCredential
	}
	return failure
}
