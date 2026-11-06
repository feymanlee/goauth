package wechat

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"testing"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

func TestExchange(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodGet || request.Host != "api.weixin.qq.com" {
			t.Errorf("unexpected request: %s %s", request.Method, request.Host)
		}
		switch request.URL.Path {
		case "/sns/oauth2/access_token":
			query := request.URL.Query()
			if query.Get("appid") != "app" || query.Get("secret") != "secret" ||
				query.Get("code") != "code" || query.Get("grant_type") != "authorization_code" {
				t.Error("invalid exchange parameters")
			}
			fmt.Fprint(writer, `{"access_token":"token","refresh_token":"refresh","scope":"snsapi_userinfo","openid":"person","unionid":"union","expires_in":7200}`)
		case "/sns/userinfo":
			if request.URL.Query().Get("access_token") != "token" || request.URL.Query().Get("openid") != "person" {
				t.Error("invalid profile parameters")
			}
			fmt.Fprint(writer, `{"openid":"person","unionid":"union","nickname":"测试用户","headimgurl":"https://example.com/avatar"}`)
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{AppID: "app", AppSecret: "secret", HTTPClient: client, FetchProfile: true})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Exchange(context.Background(), "code")
	if err != nil {
		t.Fatal(err)
	}
	if identity.Provider != goauth.WeChat || identity.AppID != "app" || identity.ID != "person" ||
		identity.UnionID != "union" || identity.SubjectType != goauth.OpenID ||
		identity.Nickname != "测试用户" || identity.Avatar != "https://example.com/avatar" || calls != 2 {
		t.Fatalf("identity=%+v calls=%d", identity, calls)
	}
	if identity.Raw["openid"] != "person" || identity.Raw["nickname"] != "测试用户" ||
		identity.TokenResponse["access_token"] != "token" || identity.TokenResponse["refresh_token"] != "refresh" ||
		identity.TokenResponse["scope"] != "snsapi_userinfo" || identity.Name != "" || identity.Email != "" {
		t.Fatalf("incomplete user: %+v", identity)
	}
}

func TestExchangeFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		token   string
		profile string
		want    error
	}{
		{"used code", `{"errcode":40163,"errmsg":"secret text"}`, "", goauth.ErrInvalidCredential},
		{"provider failure", `{"errcode":-1}`, "", goauth.ErrProvider},
		{"missing identity", `{"access_token":"token","expires_in":7200}`, "", goauth.ErrResponse},
		{"expired", `{"access_token":"token","openid":"person","expires_in":0}`, "", goauth.ErrResponse},
		{"wrong profile", `{"access_token":"token","openid":"person","expires_in":7200}`, `{"openid":"other"}`, goauth.ErrIdentityMismatch},
		{"wrong union", `{"access_token":"token","openid":"person","unionid":"union","expires_in":7200}`, `{"openid":"person","unionid":"other"}`, goauth.ErrIdentityMismatch},
		{"missing profile identity", `{"access_token":"token","openid":"person","expires_in":7200}`, `{}`, goauth.ErrResponse},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/sns/userinfo" {
					fmt.Fprint(writer, scenario.profile)
				} else {
					fmt.Fprint(writer, scenario.token)
				}
			})
			provider, err := New(Config{AppID: "app", AppSecret: "secret", HTTPClient: client, FetchProfile: scenario.profile != ""})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := provider.Exchange(context.Background(), "code")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(identity, goauth.User{}) {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
		})
	}
}

func TestInputValidationAndIdentityOnly(t *testing.T) {
	if _, err := New(Config{AppID: "app"}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatalf("missing secret: %v", err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		fmt.Fprint(writer, `{"access_token":"token","openid":"person","expires_in":7200}`)
	})
	provider, err := New(Config{AppID: "app", AppSecret: "secret", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exchange(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty code: %v calls=%d", err, calls)
	}
	identity, err := provider.Exchange(context.Background(), "code")
	if err != nil || len(identity.Raw) != 0 || identity.Nickname != "" || calls != 1 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
}
