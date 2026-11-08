package github

import (
	"context"
	"net/http"
	"net/url"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

type Config struct {
	ClientID     string
	ClientSecret string
	FetchProfile bool
	// HTTPClient supplies the client used for platform requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: token endpoints must not follow redirects.
	HTTPClient *http.Client
}

type Provider struct {
	clientID     string
	clientSecret string
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.CodeExchanger = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.ClientID, config.ClientSecret) {
		return nil, httpx.Failure(goauth.GitHub, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		clientID: config.ClientID, clientSecret: config.ClientSecret,
		fetchProfile: config.FetchProfile, http: httpx.New(goauth.GitHub, config.HTTPClient),
	}, nil
}

func (provider *Provider) Exchange(ctx context.Context, code string) (goauth.User, error) {
	if !httpx.Present(code) {
		return goauth.User{}, httpx.Failure(goauth.GitHub, "exchange", goauth.ErrInvalidCredential)
	}
	var token struct {
		AccessToken string `json:"access_token"`
		ExpiresIn   int64  `json:"expires_in"`
		Error       string `json:"error"`
	}
	var tokenResponse map[string]any
	err := provider.http.JSON(ctx, "exchange", http.MethodPost, "https://github.com/login/oauth/access_token", url.Values{
		"client_id": {provider.clientID}, "client_secret": {provider.clientSecret}, "code": {code},
	}, httpx.Capture(&token, &tokenResponse))
	if token.Error != "" {
		return goauth.User{}, rejected("exchange", token.Error)
	}
	if err != nil {
		return goauth.User{}, err
	}
	if !httpx.Present(token.AccessToken) || token.ExpiresIn < 0 {
		return goauth.User{}, httpx.Failure(goauth.GitHub, "exchange", goauth.ErrResponse)
	}
	user := goauth.User{
		Provider: goauth.GitHub, AppID: provider.clientID,
		Raw: make(map[string]any), TokenResponse: tokenResponse,
	}
	if err := provider.user(ctx, token.AccessToken, &user); err != nil {
		return goauth.User{}, err
	}
	if provider.fetchProfile {
		if err := provider.email(ctx, token.AccessToken, &user); err != nil {
			return goauth.User{}, err
		}
	}
	return user, nil
}

func (provider *Provider) user(ctx context.Context, accessToken string, user *goauth.User) error {
	var profile struct {
		Login     string           `json:"login"`
		ID        httpx.Identifier `json:"id"`
		Name      string           `json:"name"`
		Email     string           `json:"email"`
		AvatarURL string           `json:"avatar_url"`
	}
	var raw map[string]any
	err := provider.http.JSONWithHeaders(ctx, "user", http.MethodGet, "https://api.github.com/user", nil,
		map[string]string{"Authorization": "Bearer " + accessToken}, httpx.Capture(&profile, &raw))
	if err != nil {
		return err
	}
	if !httpx.Present(string(profile.ID)) {
		return httpx.Failure(goauth.GitHub, "user", goauth.ErrResponse)
	}
	user.ID = string(profile.ID)
	user.SubjectType = goauth.UserID
	user.Nickname = profile.Login
	user.Name = profile.Name
	user.Email = profile.Email
	user.Avatar = profile.AvatarURL
	user.Raw = raw
	return nil
}

func (provider *Provider) email(ctx context.Context, accessToken string, user *goauth.User) error {
	var entries []struct {
		Email    string `json:"email"`
		Primary  bool   `json:"primary"`
		Verified bool   `json:"verified"`
	}
	err := provider.http.JSONWithHeaders(ctx, "email", http.MethodGet, "https://api.github.com/user/emails", nil,
		map[string]string{"Authorization": "Bearer " + accessToken}, &entries)
	if err != nil {
		return err
	}
	for _, entry := range entries {
		if entry.Primary && entry.Verified {
			user.Email = entry.Email
			break
		}
	}
	return nil
}

func rejected(operation, code string) error {
	failure := httpx.Rejected(goauth.GitHub, operation, code)
	switch code {
	case "bad_verification_code":
		failure.Kind = goauth.ErrInvalidCredential
	case "incorrect_client_credentials", "redirect_uri_mismatch":
		failure.Kind = goauth.ErrInvalidConfig
	}
	return failure
}
