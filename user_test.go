package goauth_test

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"testing"

	"github.com/feymanlee/goauth/internal/testutil"
	"github.com/feymanlee/goauth/wechat"
)

func TestUserJSONContract(t *testing.T) {
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path == "/sns/oauth2/access_token" {
			fmt.Fprint(writer, `{"access_token":"token","expires_in":7200,"openid":"1472352","token_type":"bearer","scope":"user:email","refresh_token":"refresh","vendor":{"large_id":9007199254740993}}`)
		} else {
			fmt.Fprint(writer, `{"openid":"1472352","nickname":"overtrue","headimgurl":"https://example.com/avatar","extra":{"large_id":9007199254740993}}`)
		}
	})
	for _, fetchProfile := range []bool{false, true} {
		t.Run(fmt.Sprint(fetchProfile), func(t *testing.T) {
			provider, err := wechat.New(wechat.Config{
				AppID: "app", AppSecret: "private-secret", FetchProfile: fetchProfile, HTTPClient: client,
			})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Exchange(context.Background(), "private-code")
			if err != nil {
				t.Fatal(err)
			}
			encoded, err := json.Marshal(user)
			if err != nil {
				t.Fatal(err)
			}
			var result map[string]json.RawMessage
			if err := json.Unmarshal(encoded, &result); err != nil {
				t.Fatal(err)
			}
			for _, field := range []string{"id", "nickname", "name", "email", "avatar", "raw", "token_response", "provider", "app_id", "subject_type"} {
				if _, exists := result[field]; !exists {
					t.Fatalf("missing JSON field %s", field)
				}
			}
			if string(result["id"]) != `"1472352"` || string(result["name"]) != `""` || string(result["email"]) != `""` {
				t.Fatalf("unexpected normalized fields: %s", encoded)
			}
			if result["profile"] != nil || result["subject"] != nil ||
				bytes.Contains(encoded, []byte("private-secret")) || bytes.Contains(encoded, []byte("private-code")) {
				t.Fatalf("unexpected legacy or request fields: %s", encoded)
			}
			token := user.TokenResponse
			if token["access_token"] != "token" || token["token_type"] != "bearer" ||
				token["scope"] != "user:email" || token["refresh_token"] != "refresh" ||
				!bytes.Contains(result["token_response"], []byte(`9007199254740993`)) {
				t.Fatalf("incomplete token response: %s", encoded)
			}
			if fetchProfile {
				if user.Nickname != "overtrue" || user.Avatar != "https://example.com/avatar" ||
					!bytes.Contains(result["raw"], []byte(`9007199254740993`)) {
					t.Fatalf("incomplete profile: %s", encoded)
				}
			} else if string(result["raw"]) != "{}" || user.Nickname != "" || user.Avatar != "" {
				t.Fatalf("unexpected profile without fetch: %s", encoded)
			}
			key := user.Key()
			user.Raw["openid"] = "modified-profile"
			user.TokenResponse["openid"] = "modified-token"
			if user.Key() != key {
				t.Fatal("mutating raw responses changed the verified identity")
			}
		})
	}
}
