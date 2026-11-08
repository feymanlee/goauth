package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"os"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/alipay"
	"github.com/feymanlee/goauth/douyin"
	"github.com/feymanlee/goauth/facebook"
	"github.com/feymanlee/goauth/github"
	"github.com/feymanlee/goauth/google"
	"github.com/feymanlee/goauth/qq"
	"github.com/feymanlee/goauth/wechat"
	"github.com/feymanlee/goauth/weibo"
)

func main() {
	platform := flag.String("provider", "wechat", "wechat, qq, douyin, weibo, alipay, github, google, facebook")
	profile := flag.Bool("profile", false, "fetch authorized profile")
	subjectType := flag.String("alipay-subject", string(goauth.OpenID), "open_id or user_id")
	flag.Parse()
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	user, err := authenticate(ctx, *platform, *profile, goauth.SubjectType(*subjectType))
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := json.NewEncoder(os.Stdout).Encode(user); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}

func authenticate(ctx context.Context, platform string, profile bool, subjectType goauth.SubjectType) (goauth.User, error) {
	appID := os.Getenv("GOAUTH_APP_ID")
	secret := os.Getenv("GOAUTH_APP_SECRET")
	credential := os.Getenv("GOAUTH_CREDENTIAL")
	var exchanger goauth.CodeExchanger
	var verifier goauth.TokenVerifier
	var err error
	switch platform {
	case "wechat":
		exchanger, err = wechat.New(wechat.Config{AppID: appID, AppSecret: secret, FetchProfile: profile})
	case "qq":
		verifier, err = qq.New(qq.Config{AppID: appID, FetchProfile: profile})
	case "douyin":
		exchanger, err = douyin.New(douyin.Config{ClientKey: appID, ClientSecret: secret, FetchProfile: profile})
	case "weibo":
		verifier, err = weibo.New(weibo.Config{AppKey: appID, FetchProfile: profile})
	case "alipay":
		privateKey, readErr := os.ReadFile(os.Getenv("GOAUTH_ALIPAY_PRIVATE_KEY_FILE"))
		if readErr != nil {
			return goauth.User{}, fmt.Errorf("read application private key: %w", readErr)
		}
		publicKey, readErr := os.ReadFile(os.Getenv("GOAUTH_ALIPAY_PUBLIC_KEY_FILE"))
		if readErr != nil {
			return goauth.User{}, fmt.Errorf("read Alipay public key: %w", readErr)
		}
		exchanger, err = alipay.New(alipay.Config{
			AppID: appID, PrivateKeyPEM: string(privateKey), AlipayPublicKeyPEM: string(publicKey),
			SubjectType: subjectType, FetchProfile: profile,
		})
	case "github":
		exchanger, err = github.New(github.Config{ClientID: appID, ClientSecret: secret, FetchProfile: profile})
	case "google":
		verifier, err = google.New(google.Config{ClientID: appID})
	case "facebook":
		verifier, err = facebook.New(facebook.Config{AppID: appID, AppSecret: secret, FetchProfile: profile})
	default:
		return goauth.User{}, errors.New("unsupported provider")
	}
	if err != nil {
		return goauth.User{}, err
	}
	if exchanger != nil {
		return exchanger.Exchange(ctx, credential)
	}
	return verifier.Verify(ctx, credential)
}
