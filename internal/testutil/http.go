package testutil

import (
	"net/http"
	"net/http/httptest"
	"net/url"
	"testing"
)

type RoundTripFunc func(*http.Request) (*http.Response, error)

func (transport RoundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return transport(request)
}

func Client(t *testing.T, handler http.HandlerFunc) *http.Client {
	t.Helper()
	server := httptest.NewServer(handler)
	t.Cleanup(server.Close)
	target, err := url.Parse(server.URL)
	if err != nil {
		t.Fatal(err)
	}
	base := http.DefaultTransport.(*http.Transport).Clone()
	t.Cleanup(base.CloseIdleConnections)
	return &http.Client{
		Transport: RoundTripFunc(func(request *http.Request) (*http.Response, error) {
			forwarded := request.Clone(request.Context())
			forwarded.Host = request.URL.Host
			forwarded.URL.Scheme = target.Scheme
			forwarded.URL.Host = target.Host
			return base.RoundTrip(forwarded)
		}),
	}
}
