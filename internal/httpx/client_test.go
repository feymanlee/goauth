package httpx

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

func TestResponseFailures(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		status int
		body   string
		want   error
	}{
		{"http failure", 503, "secret body", goauth.ErrTransport},
		{"redirect", 302, "", goauth.ErrTransport},
		{"malformed", 200, `{"`, goauth.ErrResponse},
		{"null", 200, `null`, goauth.ErrResponse},
		{"array", 200, `[]`, goauth.ErrResponse},
		{"trailing data", 200, `{} {}`, goauth.ErrResponse},
		{"oversized", 200, strings.Repeat("x", maxResponseBytes+1), goauth.ErrResponse},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			calls := 0
			supplied := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				calls++
				writer.Header().Set("Location", "https://attacker.invalid/collect")
				writer.WriteHeader(scenario.status)
				fmt.Fprint(writer, scenario.body)
			})
			client := New(goauth.QQ, supplied)
			var result map[string]any
			err := client.JSON(context.Background(), "verify", http.MethodGet,
				"https://graph.qq.com/oauth2.0/me", url.Values{"access_token": {"sensitive-token"}}, &result)
			if !errors.Is(err, scenario.want) || calls != 1 {
				t.Fatalf("error=%v calls=%d", err, calls)
			}
			if strings.Contains(err.Error(), "sensitive") || strings.Contains(err.Error(), "secret body") {
				t.Fatal("error leaks credentials or response")
			}
		})
	}
}

func TestCancellationAndTimeout(t *testing.T) {
	for _, scenario := range []struct {
		name    string
		timeout time.Duration
		cancel  bool
		want    error
	}{
		{"canceled", time.Second, true, context.Canceled},
		{"timeout", 20 * time.Millisecond, false, context.DeadlineExceeded},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			supplied := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				<-request.Context().Done()
			})
			supplied.Timeout = scenario.timeout
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			if scenario.cancel {
				cancel()
			}
			_, err := New(goauth.WeChat, supplied).Do(ctx, "exchange", http.MethodGet,
				"https://api.weixin.qq.com/test", nil)
			if !errors.Is(err, scenario.want) {
				t.Fatalf("got %v, want %v", err, scenario.want)
			}
		})
	}
}

func TestTransportErrorRedaction(t *testing.T) {
	supplied := &http.Client{Transport: testutil.RoundTripFunc(func(*http.Request) (*http.Response, error) {
		return nil, errors.New("secret-token secret-app-key")
	})}
	_, err := New(goauth.WeChat, supplied).Do(context.Background(), "exchange", http.MethodGet,
		"https://api.weixin.qq.com/test", url.Values{"secret": {"secret-app-key"}})
	if !errors.Is(err, goauth.ErrTransport) || strings.Contains(fmt.Sprintf("%+v", err), "secret") {
		t.Fatalf("unsafe or unexpected error: %v", err)
	}
	if supplied.Timeout != 0 || supplied.CheckRedirect != nil {
		t.Fatal("caller HTTP client was modified")
	}
}
