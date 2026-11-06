package weibo

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

func TestHTTPErrorHandling(t *testing.T) {
	for _, scenario := range []struct {
		name string
		body string
		want error
	}{
		{"token rejection", `{"error_code":21317,"error":"token_rejected: private-token"}`, goauth.ErrInvalidCredential},
		{"success body on failed status", `{"uid":"42","appkey":"123","expire_in":7200}`, goauth.ErrTransport},
		{"malformed rejection", `not JSON: private-token`, goauth.ErrTransport},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(writer, scenario.body)
			})
			provider, err := New(Config{AppKey: "123", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := provider.Verify(context.Background(), "private-token")
			if !errors.Is(err, scenario.want) || identity.ID != "" || strings.Contains(err.Error(), "private-token") {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
		})
	}
}

func TestVerify(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Host != "api.weibo.com" {
			t.Errorf("unexpected host: %s", request.Host)
		}
		switch request.URL.Path {
		case "/oauth2/get_token_info":
			if request.Method != http.MethodPost || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("expected form POST")
			}
			if err := request.ParseForm(); err != nil || request.PostForm.Get("access_token") != "token" {
				t.Error("missing access token")
			}
			fmt.Fprint(writer, `{"uid":9007199254740993,"appkey":"123","expire_in":7200}`)
		case "/2/users/show.json":
			if request.URL.Query().Get("uid") != "9007199254740993" {
				t.Error("UID lost precision")
			}
			fmt.Fprint(writer, `{"id":9007199254740993,"idstr":"9007199254740993","screen_name":"测试","name":"显示名称","avatar_large":"https://example.com/avatar","extra":{"enabled":true,"value":null}}`)
		default:
			t.Errorf("unexpected path: %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{AppKey: "123", FetchProfile: true, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Verify(context.Background(), "token")
	if err != nil || identity.ID != "9007199254740993" || identity.AppID != "123" ||
		identity.Provider != goauth.Weibo || identity.SubjectType != goauth.UserID ||
		identity.Nickname != "测试" || calls != 2 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
	if identity.Name != "显示名称" || identity.Email != "" || identity.Raw["id"] != json.Number("9007199254740993") ||
		identity.TokenResponse["access_token"] != "token" || len(identity.TokenResponse) != 1 {
		t.Fatalf("incomplete user or lost precision: %+v", identity)
	}
	extra, valid := identity.Raw["extra"].(map[string]any)
	if !valid || extra["enabled"] != true || extra["value"] != nil {
		t.Fatalf("lost platform fields: %#v", identity.Raw)
	}
}

func TestVerifyFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		token   string
		profile string
		want    error
	}{
		{"wrong app", `{"uid":"42","appkey":"other","expire_in":7200}`, "", goauth.ErrIdentityMismatch},
		{"expired", `{"uid":"42","appkey":"123","expire_in":0}`, "", goauth.ErrInvalidCredential},
		{"negative expiry", `{"uid":"42","appkey":"123","expire_in":-42}`, "", goauth.ErrInvalidCredential},
		{"negative string expiry", `{"uid":"42","appkey":"123","expire_in":"-42"}`, "", goauth.ErrInvalidCredential},
		{"missing expiry", `{"uid":"42","appkey":"123"}`, "", goauth.ErrResponse},
		{"missing user", `{"appkey":"123","expire_in":7200}`, "", goauth.ErrResponse},
		{"zero user", `{"uid":0,"appkey":"123","expire_in":7200}`, "", goauth.ErrResponse},
		{"invalid numeric user", `{"uid":42.5,"appkey":"123","expire_in":7200}`, "", goauth.ErrResponse},
		{"rejected token", `{"error_code":21327}`, "", goauth.ErrInvalidCredential},
		{"string rejection", `{"error_code":"21327"}`, "", goauth.ErrInvalidCredential},
		{"service error", `{"error_code":10001}`, "", goauth.ErrProvider},
		{"wrong profile", `{"uid":"42","appkey":"123","expire_in":7200}`, `{"id":43}`, goauth.ErrIdentityMismatch},
		{"inconsistent profile", `{"uid":"42","appkey":"123","expire_in":7200}`, `{"id":43,"idstr":"42"}`, goauth.ErrIdentityMismatch},
		{"empty profile", `{"uid":"42","appkey":"123","expire_in":7200}`, `{}`, goauth.ErrResponse},
		{"profile denied", `{"uid":"42","appkey":"123","expire_in":7200}`, `{"error_code":10023}`, goauth.ErrProvider},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/oauth2/get_token_info" {
					fmt.Fprint(writer, scenario.token)
				} else {
					fmt.Fprint(writer, scenario.profile)
				}
			})
			provider, err := New(Config{AppKey: "123", FetchProfile: scenario.profile != "", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			identity, err := provider.Verify(context.Background(), "token")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(identity, goauth.User{}) {
				t.Fatalf("identity=%+v error=%v", identity, err)
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
		fmt.Fprint(writer, `{"uid":"42","appkey":123,"expire_in":"7200"}`)
	})
	provider, err := New(Config{AppKey: "123", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Verify(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty token: %v", err)
	}
	identity, err := provider.Verify(context.Background(), "token")
	if err != nil || len(identity.Raw) != 0 || identity.Nickname != "" || calls != 1 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
}
