package facebook

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

func validToken(expiresAt int64) string {
	return fmt.Sprintf(`{"data":{"app_id":"123","user_id":"42","is_valid":true,"expires_at":%d}}`, expiresAt)
}

func TestVerify(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Host != "graph.facebook.com" || request.Method != http.MethodGet {
			t.Errorf("unexpected request: %s %s", request.Method, request.Host)
		}
		switch request.URL.Path {
		case "/" + graphAPIVersion + "/debug_token":
			query := request.URL.Query()
			if query.Get("input_token") != "token" || query.Get("access_token") != "123|secret" {
				t.Error("debug_token must use the input token and application credential")
			}
			fmt.Fprint(writer, validToken(time.Now().Add(time.Hour).Unix()))
		case "/" + graphAPIVersion + "/me":
			query := request.URL.Query()
			if query.Get("access_token") != "token" || !strings.Contains(query.Get("fields"), "id,name,email,picture") {
				t.Error("profile must use the verified token and profile fields")
			}
			fmt.Fprint(writer, `{"id":"42","name":"Test User","email":"person@example.com","picture":{"data":{"url":"https://example.com/avatar"}}}`)
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{AppID: "123", AppSecret: "secret", FetchProfile: true, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.Verify(context.Background(), "token")
	if err != nil || user.Provider != goauth.Facebook || user.AppID != "123" ||
		user.ID != "42" || user.SubjectType != goauth.UserID ||
		user.Name != "Test User" || user.Email != "person@example.com" ||
		user.Avatar != "https://example.com/avatar" || calls != 2 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
	if user.Raw["name"] != "Test User" || user.TokenResponse["access_token"] != "token" ||
		len(user.TokenResponse) != 1 || user.UnionID != "" {
		t.Fatalf("incomplete user: %+v", user)
	}
}

func TestVerifyFailures(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		token   string
		profile string
		want    error
	}{
		{"rejected token", `{"error":{"message":"secret token","type":"OAuthException","code":190}}`, "", goauth.ErrInvalidCredential},
		{"invalid token", `{"data":{"app_id":"123","user_id":"42","is_valid":false}}`, "", goauth.ErrInvalidCredential},
		{"missing data", `{}`, "", goauth.ErrResponse},
		{"different app", fmt.Sprintf(`{"data":{"app_id":"other","user_id":"42","is_valid":true,"expires_at":%d}}`, time.Now().Add(time.Hour).Unix()), "", goauth.ErrIdentityMismatch},
		{"missing user", `{"data":{"app_id":"123","is_valid":true}}`, "", goauth.ErrResponse},
		{"expired token", validToken(time.Now().Add(-time.Minute).Unix()), "", goauth.ErrInvalidCredential},
		{"wrong profile user", validToken(time.Now().Add(time.Hour).Unix()), `{"id":"43","name":"Test User"}`, goauth.ErrIdentityMismatch},
		{"profile denied", validToken(time.Now().Add(time.Hour).Unix()), `{"error":{"message":"secret","code":190}}`, goauth.ErrInvalidCredential},
		{"empty profile", validToken(time.Now().Add(time.Hour).Unix()), `{}`, goauth.ErrResponse},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == "/"+graphAPIVersion+"/debug_token" {
					fmt.Fprint(writer, scenario.token)
				} else {
					fmt.Fprint(writer, scenario.profile)
				}
			})
			provider, err := New(Config{AppID: "123", AppSecret: "secret", FetchProfile: true, HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Verify(context.Background(), "token")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) {
				t.Fatalf("user=%+v error=%v", user, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks response: %v", err)
			}
		})
	}
}

func TestHTTPErrorHandling(t *testing.T) {
	for _, scenario := range []struct {
		name string
		body string
		want error
	}{
		{"rejection status", `{"error":{"message":"secret","code":190}}`, goauth.ErrInvalidCredential},
		{"success body on failed status", validToken(time.Now().Add(time.Hour).Unix()), goauth.ErrTransport},
		{"malformed rejection", `not JSON: secret`, goauth.ErrTransport},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				writer.WriteHeader(http.StatusUnauthorized)
				fmt.Fprint(writer, scenario.body)
			})
			provider, err := New(Config{AppID: "123", AppSecret: "secret", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Verify(context.Background(), "token")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) {
				t.Fatalf("user=%+v error=%v", user, err)
			}
		})
	}
}

func TestValidationAndIdentityOnly(t *testing.T) {
	if _, err := New(Config{AppID: "123"}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatal(err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		fmt.Fprint(writer, validToken(time.Now().Add(time.Hour).Unix()))
	})
	provider, err := New(Config{AppID: "123", AppSecret: "secret", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Verify(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty token: %v calls=%d", err, calls)
	}
	user, err := provider.Verify(context.Background(), "token")
	if err != nil || user.ID != "42" || user.Name != "" || len(user.Raw) != 0 || calls != 1 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
}
