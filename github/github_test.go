package github

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"reflect"
	"strings"
	"testing"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

const (
	validToken = `{"access_token":"token","token_type":"bearer","scope":"read:user","expires_in":28800}`
	validUser  = `{"login":"octocat","id":58231,"name":"Octo Cat","avatar_url":"https://example.com/avatar"}`
	validEmail = `[{"email":"other@example.com","primary":false,"verified":true},{"email":"octo@example.com","primary":true,"verified":true}]`
)

func TestExchange(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Host != "github.com" && request.Host != "api.github.com" {
			t.Errorf("unexpected host: %s", request.Host)
		}
		switch request.URL.Path {
		case "/login/oauth/access_token":
			if request.Method != http.MethodPost || request.Header.Get("Accept") != "application/json" {
				t.Error("token exchange requires POST with JSON accept")
			}
			if err := request.ParseForm(); err != nil || request.PostForm.Get("client_id") != "app" ||
				request.PostForm.Get("client_secret") != "secret" || request.PostForm.Get("code") != "code" {
				t.Error("invalid exchange parameters")
			}
			fmt.Fprint(writer, validToken)
		case "/user":
			if request.Method != http.MethodGet || request.Header.Get("Authorization") != "Bearer token" {
				t.Error("user request requires bearer authorization")
			}
			fmt.Fprint(writer, validUser)
		case "/user/emails":
			if request.Header.Get("Authorization") != "Bearer token" {
				t.Error("email request requires bearer authorization")
			}
			fmt.Fprint(writer, validEmail)
		default:
			t.Errorf("unexpected path %s", request.URL.Path)
			writer.WriteHeader(404)
		}
	})
	provider, err := New(Config{ClientID: "app", ClientSecret: "secret", FetchProfile: true, HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.Exchange(context.Background(), "code")
	if err != nil || user.Provider != goauth.GitHub || user.AppID != "app" ||
		user.ID != "58231" || user.SubjectType != goauth.UserID ||
		user.Nickname != "octocat" || user.Name != "Octo Cat" ||
		user.Email != "octo@example.com" || user.Avatar != "https://example.com/avatar" || calls != 3 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
	if user.Raw["login"] != "octocat" || user.TokenResponse["access_token"] != "token" ||
		user.TokenResponse["scope"] != "read:user" || user.UnionID != "" {
		t.Fatalf("incomplete user: %+v", user)
	}
}

func TestExchangeFailures(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		token  string
		user   string
		emails string
		want   error
	}{
		{"used code", `{"error":"bad_verification_code","error_description":"secret text"}`, "", "", goauth.ErrInvalidCredential},
		{"wrong secret", `{"error":"incorrect_client_credentials"}`, "", "", goauth.ErrInvalidConfig},
		{"redirect mismatch", `{"error":"redirect_uri_mismatch"}`, "", "", goauth.ErrInvalidConfig},
		{"missing token", `{"token_type":"bearer"}`, "", "", goauth.ErrResponse},
		{"missing identity", validToken, `{}`, "", goauth.ErrResponse},
		{"email denied", validToken, validUser, `{"message":"Not Found"}`, goauth.ErrTransport},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				switch request.URL.Path {
				case "/login/oauth/access_token":
					fmt.Fprint(writer, scenario.token)
				case "/user":
					fmt.Fprint(writer, scenario.user)
				default:
					writer.WriteHeader(404)
					fmt.Fprint(writer, scenario.emails)
				}
			})
			provider, err := New(Config{ClientID: "app", ClientSecret: "secret", FetchProfile: scenario.emails != "", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Exchange(context.Background(), "code")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) {
				t.Fatalf("user=%+v error=%v", user, err)
			}
		})
	}
}

func TestHTTPErrorHandling(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		badPath string
		status  int
		body    string
		want    error
	}{
		{"rejection status", "/login/oauth/access_token", 400, `{"error":"bad_verification_code","error_description":"secret"}`, goauth.ErrInvalidCredential},
		{"user body on failed status", "/user", 401, validUser, goauth.ErrTransport},
		{"malformed rejection", "/login/oauth/access_token", 400, `not JSON: secret`, goauth.ErrTransport},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				if request.URL.Path == scenario.badPath {
					writer.WriteHeader(scenario.status)
					fmt.Fprint(writer, scenario.body)
					return
				}
				fmt.Fprint(writer, validToken)
			})
			provider, err := New(Config{ClientID: "app", ClientSecret: "secret", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Exchange(context.Background(), "code")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) {
				t.Fatalf("user=%+v error=%v", user, err)
			}
			if strings.Contains(err.Error(), "secret") {
				t.Fatalf("error leaks response: %v", err)
			}
		})
	}
}

func TestExchangeWithoutExpiry(t *testing.T) {
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path == "/login/oauth/access_token" {
			fmt.Fprint(writer, `{"access_token":"token","token_type":"bearer","scope":"read:user"}`)
			return
		}
		fmt.Fprint(writer, validUser)
	})
	provider, err := New(Config{ClientID: "app", ClientSecret: "secret", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.Exchange(context.Background(), "code")
	if err != nil || user.ID != "58231" || user.SubjectType != goauth.UserID || calls != 2 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
}

func TestValidationAndIdentityOnly(t *testing.T) {
	if _, err := New(Config{ClientID: "app"}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatal(err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.URL.Path == "/login/oauth/access_token" {
			fmt.Fprint(writer, validToken)
		} else {
			fmt.Fprint(writer, validUser)
		}
	})
	provider, err := New(Config{ClientID: "app", ClientSecret: "secret", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Exchange(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty code: %v calls=%d", err, calls)
	}
	user, err := provider.Exchange(context.Background(), "code")
	if err != nil || user.Email != "" || calls != 2 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
	if user.Raw["login"] == nil {
		t.Fatalf("user identity call missing raw data: %+v", user)
	}
}
