package douyin

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

const validToken = `{"data":{"error_code":0,"access_token":"token","refresh_token":"refresh","scope":"user_info","open_id":"person","expires_in":7200},"message":"success"}`

func TestExchange(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodPost || request.Host != "open.douyin.com" {
			t.Errorf("unexpected request %s %s", request.Method, request.Host)
		}
		switch request.URL.Path {
		case "/oauth/access_token/":
			if request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
				t.Error("token exchange requires form encoding")
			}
			if err := request.ParseForm(); err != nil {
				t.Error(err)
			}
			if request.PostForm.Get("client_key") != "app" || request.PostForm.Get("client_secret") != "secret" ||
				request.PostForm.Get("code") != "code+ /" || request.PostForm.Get("grant_type") != "authorization_code" {
				t.Error("incorrect exchange parameters")
			}
			fmt.Fprint(writer, validToken)
		case "/oauth/userinfo/":
			if request.Header.Get("Content-Type") != "application/json" {
				t.Error("profile requires JSON encoding")
			}
			var body map[string]string
			if json.NewDecoder(request.Body).Decode(&body) != nil ||
				body["access_token"] != "token" || body["open_id"] != "person" {
				t.Error("invalid profile body")
			}
			fmt.Fprint(writer, `{"err_no":0,"data":{"error_code":"0","open_id":"person","client_key":"app","union_id":"union","nickname":"测试","avatar":"https://example.com/avatar"}}`)
		default:
			t.Errorf("unexpected path: %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{ClientKey: "app", ClientSecret: "secret", FetchProfile: true, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Exchange(context.Background(), "code+ /")
	if err != nil || identity.Provider != goauth.Douyin || identity.AppID != "app" ||
		identity.ID != "person" || identity.SubjectType != goauth.OpenID ||
		identity.UnionID != "union" || identity.Nickname != "测试" || calls != 2 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
	if identity.Raw["open_id"] != "person" || identity.Raw["client_key"] != "app" ||
		identity.TokenResponse["access_token"] != "token" || identity.TokenResponse["refresh_token"] != "refresh" ||
		identity.TokenResponse["scope"] != "user_info" || identity.TokenResponse["data"] != nil || identity.Raw["data"] != nil {
		t.Fatalf("unexpected raw response layer: %+v", identity)
	}
}

func TestHTTPErrorHandling(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		profile bool
		badPath string
		body    string
		want    error
	}{
		{"token rejection", false, "/oauth/access_token/", `{"data":{"error_code":28001008}}`, goauth.ErrInvalidCredential},
		{"success body on failed status", false, "/oauth/access_token/", validToken, goauth.ErrTransport},
		{"malformed rejection", false, "/oauth/access_token/", `not JSON: secret`, goauth.ErrTransport},
		{"profile rejection", true, "/oauth/userinfo/", `{"err_no":28001008}`, goauth.ErrInvalidCredential},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if request.URL.Path == scenario.badPath {
					writer.WriteHeader(http.StatusUnauthorized)
					fmt.Fprint(writer, scenario.body)
					return
				}
				switch request.URL.Path {
				case "/oauth/access_token/":
					fmt.Fprint(writer, validToken)
				default:
					fmt.Fprint(writer, `{"err_no":0,"data":{"error_code":0,"open_id":"person","client_key":"app"}}`)
				}
			})
			provider, err := New(Config{ClientKey: "app", ClientSecret: "secret", FetchProfile: scenario.profile, HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Exchange(context.Background(), "code")
			expected := 1
			if scenario.profile {
				expected = 2
			}
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) || calls != expected {
				t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks response: %v", err)
			}
		})
	}
}

func TestExchangeFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		token   string
		profile string
		want    error
	}{
		{"invalid code", `{"data":{"error_code":10007}}`, "", goauth.ErrInvalidCredential},
		{"wrong app", `{"data":{"error_code":10014}}`, "", goauth.ErrIdentityMismatch},
		{"service failure", `{"data":{"error_code":10003}}`, "", goauth.ErrProvider},
		{"missing data", `{}`, "", goauth.ErrResponse},
		{"noncanonical data key", `{"DATA":{"error_code":0,"access_token":"token","open_id":"person","expires_in":7200}}`, "", goauth.ErrResponse},
		{"missing status", `{"data":{"access_token":"token","open_id":"person","expires_in":7200}}`, "", goauth.ErrResponse},
		{"missing identity", `{"data":{"error_code":0,"access_token":"token","expires_in":7200}}`, "", goauth.ErrResponse},
		{"wrong profile user", validToken, `{"err_no":0,"data":{"open_id":"other","client_key":"app"}}`, goauth.ErrIdentityMismatch},
		{"wrong profile app", validToken, `{"err_no":0,"data":{"open_id":"person","client_key":"other"}}`, goauth.ErrIdentityMismatch},
		{"missing profile app", validToken, `{"err_no":0,"data":{"open_id":"person"}}`, goauth.ErrResponse},
		{"missing profile status", validToken, `{"data":{"open_id":"person","client_key":"app"}}`, goauth.ErrResponse},
		{"missing profile data", validToken, `{"err_no":0}`, goauth.ErrResponse},
		{"noncanonical profile data key", validToken, `{"err_no":0,"DATA":{"open_id":"person","client_key":"app"}}`, goauth.ErrResponse},
		{"profile rejected", validToken, `{"err_no":28001008,"data":{"error_code":10008}}`, goauth.ErrInvalidCredential},
		{"nested rejection", validToken, `{"err_no":0,"data":{"error_code":"10008"}}`, goauth.ErrInvalidCredential},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/oauth/access_token/" {
					fmt.Fprint(writer, scenario.token)
				} else {
					fmt.Fprint(writer, scenario.profile)
				}
			})
			provider, err := New(Config{ClientKey: "app", ClientSecret: "secret", FetchProfile: scenario.profile != "", HTTPClient: client})
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

func TestValidationAndIdentityOnly(t *testing.T) {
	if _, err := New(Config{ClientKey: "app"}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatal(err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		fmt.Fprint(writer, validToken)
	})
	provider, err := New(Config{ClientKey: "app", ClientSecret: "secret", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exchange(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty code: %v", err)
	}
	identity, err := provider.Exchange(context.Background(), "code")
	if err != nil || len(identity.Raw) != 0 || identity.Nickname != "" || calls != 1 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
}
