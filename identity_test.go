package goauth_test

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"sync"
	"testing"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
	"github.com/feymanlee/goauth/wechat"
)

func TestConcurrentApplicationsRemainIsolated(t *testing.T) {
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, `{"access_token":"private-access-token","openid":"same-subject","unionid":"same-union","expires_in":7200}`)
	})
	var providers []*wechat.Provider
	for _, appID := range []string{"first-app", "second-app"} {
		provider, err := wechat.New(wechat.Config{AppID: appID, AppSecret: "private-secret", HTTPClient: client})
		if err != nil {
			t.Fatal(err)
		}
		providers = append(providers, provider)
	}
	var workers sync.WaitGroup
	results := make(chan goauth.User, 20)
	for index := 0; index < 20; index++ {
		provider := providers[index%len(providers)]
		workers.Add(1)
		go func() {
			defer workers.Done()
			identity, err := provider.Exchange(context.Background(), "private-code")
			if err != nil {
				t.Error(err)
				return
			}
			results <- identity
		}()
	}
	workers.Wait()
	close(results)
	counts := make(map[goauth.IdentityKey]int)
	for identity := range results {
		counts[identity.Key()]++
		encoded, err := json.Marshal(identity.Identity())
		if err != nil {
			t.Fatal(err)
		}
		if strings.Contains(string(encoded), "private-") {
			t.Fatalf("identity exposes credentials: %s", encoded)
		}
		if identity.TokenResponse["access_token"] != "private-access-token" {
			t.Fatal("user must retain the token response")
		}
		if identity.Raw["modified"] != nil {
			t.Fatal("raw maps are shared across requests")
		}
		identity.TokenResponse["access_token"] = "modified"
		identity.Raw["modified"] = true
	}
	if len(counts) != 2 {
		t.Fatalf("application identities merged: %+v", counts)
	}
	for key, count := range counts {
		if key.Subject != "same-subject" || key.SubjectType != goauth.OpenID || key.Provider != goauth.WeChat || count != 10 {
			t.Fatalf("unexpected identity key %v count=%d", key, count)
		}
	}
}
