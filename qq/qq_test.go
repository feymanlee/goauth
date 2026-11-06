package qq

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

func TestVerify(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Host != "graph.qq.com" || request.Method != http.MethodGet {
			t.Errorf("unexpected request: %s %s", request.Method, request.Host)
		}
		query := request.URL.Query()
		if query.Get("access_token") != "token" {
			t.Error("missing token")
		}
		switch request.URL.Path {
		case "/oauth2.0/me":
			if query.Get("fmt") != "json" {
				t.Error("JSON format required")
			}
			fmt.Fprint(writer, `{"client_id":"123","openid":"person","unionid":"union"}`)
		case "/user/get_user_info":
			if query.Get("openid") != "person" || query.Get("oauth_consumer_key") != "123" {
				t.Error("profile must use verified identity")
			}
			fmt.Fprint(writer, `{"ret":0,"nickname":"测试","figureurl_qq_1":"https://example.com/small"}`)
		default:
			t.Errorf("unexpected path: %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{AppID: "123", FetchProfile: true, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Verify(context.Background(), "token")
	if err != nil || identity.ID != "person" || identity.AppID != "123" ||
		identity.Provider != goauth.QQ || identity.SubjectType != goauth.OpenID ||
		identity.UnionID != "union" || identity.Nickname != "测试" ||
		identity.Avatar != "https://example.com/small" || calls != 2 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
	if identity.Raw["figureurl_qq_1"] != identity.Avatar ||
		identity.TokenResponse["access_token"] != "token" || len(identity.TokenResponse) != 1 ||
		identity.Name != "" || identity.Email != "" {
		t.Fatalf("incomplete user: %+v", identity)
	}
}

func TestVerifyFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		token   string
		profile string
		want    error
	}{
		{"different app", `{"client_id":"other","openid":"person"}`, "", goauth.ErrIdentityMismatch},
		{"missing app", `{"openid":"person"}`, "", goauth.ErrResponse},
		{"missing user", `{"client_id":"123"}`, "", goauth.ErrResponse},
		{"rejected", `{"error":100016,"error_description":"secret"}`, "", goauth.ErrInvalidCredential},
		{"empty profile", `{"client_id":"123","openid":"person"}`, `{}`, goauth.ErrResponse},
		{"profile denied", `{"client_id":"123","openid":"person"}`, `{"ret":100030}`, goauth.ErrProvider},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.URL.Path == "/oauth2.0/me" {
					fmt.Fprint(writer, scenario.token)
				} else {
					fmt.Fprint(writer, scenario.profile)
				}
			})
			provider, err := New(Config{AppID: "123", FetchProfile: true, HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := provider.Verify(context.Background(), "token")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(identity, goauth.User{}) {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
			if scenario.profile == "" && calls != 1 {
				t.Fatal("requested profile after verification failed")
			}
		})
	}
}

func TestValidationAndIdentityOnly(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatal(err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		fmt.Fprint(writer, `{"client_id":123,"openid":"person"}`)
	})
	provider, err := New(Config{AppID: "123", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Verify(context.Background(), ""); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty credential: %v", err)
	}
	identity, err := provider.Verify(context.Background(), "token")
	if err != nil || len(identity.Raw) != 0 || identity.Nickname != "" || calls != 1 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
}
