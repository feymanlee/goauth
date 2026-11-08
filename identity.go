package goauth

import "context"

type Provider string

const (
	WeChat   Provider = "wechat"
	QQ       Provider = "qq"
	Douyin   Provider = "douyin"
	Weibo    Provider = "weibo"
	Alipay   Provider = "alipay"
	GitHub   Provider = "github"
	Google   Provider = "google"
	Facebook Provider = "facebook"
)

type SubjectType string

const (
	OpenID SubjectType = "open_id"
	UserID SubjectType = "user_id"
)

type Identity struct {
	Provider    Provider    `json:"provider"`
	AppID       string      `json:"app_id"`
	Subject     string      `json:"subject"`
	SubjectType SubjectType `json:"subject_type"`
	UnionID     string      `json:"union_id,omitempty"`
}

type IdentityKey struct {
	Provider    Provider
	AppID       string
	SubjectType SubjectType
	Subject     string
}

func (identity Identity) Key() IdentityKey {
	return IdentityKey{
		Provider: identity.Provider, AppID: identity.AppID,
		SubjectType: identity.SubjectType, Subject: identity.Subject,
	}
}

type CodeExchanger interface {
	Exchange(ctx context.Context, code string) (User, error)
}

type TokenVerifier interface {
	Verify(ctx context.Context, accessToken string) (User, error)
}
