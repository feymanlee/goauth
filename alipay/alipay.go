package alipay

import (
	"context"
	"crypto/rsa"
	"net/http"
	"net/url"
	"strconv"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

type Config struct {
	AppID              string
	PrivateKeyPEM      string
	AlipayPublicKeyPEM string
	SubjectType        goauth.SubjectType
	FetchProfile       bool
	// HTTPClient supplies the client used for platform requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: the gateway must not follow redirects.
	HTTPClient *http.Client
}

type Provider struct {
	appID        string
	privateKey   *rsa.PrivateKey
	publicKey    *rsa.PublicKey
	subjectType  goauth.SubjectType
	fetchProfile bool
	http         *httpx.Client
}

var _ goauth.CodeExchanger = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.AppID) {
		return nil, invalidConfig()
	}
	subjectType := config.SubjectType
	if subjectType == "" {
		subjectType = goauth.OpenID
	}
	if subjectType != goauth.OpenID && subjectType != goauth.UserID {
		return nil, invalidConfig()
	}
	privateKey, err := parsePrivateKey(config.PrivateKeyPEM)
	if err != nil {
		return nil, err
	}
	publicKey, err := parsePublicKey(config.AlipayPublicKeyPEM)
	if err != nil {
		return nil, err
	}
	return &Provider{
		appID: config.AppID, privateKey: privateKey, publicKey: publicKey,
		subjectType: subjectType, fetchProfile: config.FetchProfile,
		http: httpx.New(goauth.Alipay, config.HTTPClient),
	}, nil
}

func (provider *Provider) Exchange(ctx context.Context, code string) (goauth.User, error) {
	if !httpx.Present(code) {
		return goauth.User{}, httpx.Failure(goauth.Alipay, "exchange", goauth.ErrInvalidCredential)
	}
	var token struct {
		AccessToken string           `json:"access_token"`
		ExpiresIn   httpx.Identifier `json:"expires_in"`
		OpenID      string           `json:"open_id"`
		UserID      string           `json:"user_id"`
		UnionID     string           `json:"union_id"`
	}
	var tokenResponse map[string]any
	err := provider.call(ctx, "exchange", "alipay.system.oauth.token", url.Values{
		"grant_type": {"authorization_code"}, "code": {code},
	}, httpx.Capture(&token, &tokenResponse))
	if err != nil {
		return goauth.User{}, err
	}
	subject := provider.subject(token.OpenID, token.UserID)
	expires, parseErr := strconv.ParseInt(string(token.ExpiresIn), 10, 64)
	if !httpx.Present(token.AccessToken, subject) || parseErr != nil || expires <= 0 {
		return goauth.User{}, httpx.Failure(goauth.Alipay, "exchange", goauth.ErrResponse)
	}
	user := goauth.User{
		Provider: goauth.Alipay, AppID: provider.appID, ID: subject, SubjectType: provider.subjectType,
		UnionID: token.UnionID,
		Raw:     make(map[string]any), TokenResponse: tokenResponse,
	}
	if provider.fetchProfile {
		if err := provider.profile(ctx, token.AccessToken, &user); err != nil {
			return goauth.User{}, err
		}
	}
	return user, nil
}

func (provider *Provider) subject(openID, userID string) string {
	if provider.subjectType == goauth.UserID {
		return userID
	}
	return openID
}

func (provider *Provider) profile(ctx context.Context, accessToken string, user *goauth.User) error {
	var profile struct {
		Code     string `json:"code"`
		OpenID   string `json:"open_id"`
		UserID   string `json:"user_id"`
		Nickname string `json:"nick_name"`
		Name     string `json:"user_name"`
		Email    string `json:"email"`
		Avatar   string `json:"avatar"`
	}
	var raw map[string]any
	if err := provider.call(ctx, "profile", "alipay.user.info.share", url.Values{
		"auth_token": {accessToken},
	}, httpx.Capture(&profile, &raw)); err != nil {
		return err
	}
	subject := provider.subject(profile.OpenID, profile.UserID)
	if profile.Code != "10000" || !httpx.Present(subject) {
		return httpx.Failure(goauth.Alipay, "profile", goauth.ErrResponse)
	}
	if subject != user.ID {
		return httpx.Failure(goauth.Alipay, "profile", goauth.ErrIdentityMismatch)
	}
	user.Nickname = profile.Nickname
	user.Name = profile.Name
	user.Email = profile.Email
	user.Avatar = profile.Avatar
	user.Raw = raw
	return nil
}
