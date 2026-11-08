package httpx

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/feymanlee/goauth"
)

const maxResponseBytes = 1 << 20

type Client struct {
	provider goauth.Provider
	client   *http.Client
}

func New(provider goauth.Provider, supplied *http.Client) *Client {
	client := http.Client{Timeout: 10 * time.Second}
	if supplied != nil {
		client = *supplied
		if client.Timeout <= 0 {
			client.Timeout = 10 * time.Second
		}
	}
	client.CheckRedirect = func(*http.Request, []*http.Request) error {
		return http.ErrUseLastResponse
	}
	return &Client{provider: provider, client: &client}
}

func Failure(provider goauth.Provider, operation string, kind error) *goauth.Error {
	return &goauth.Error{Provider: provider, Operation: operation, Kind: kind}
}

func Rejected(provider goauth.Provider, operation, code string) *goauth.Error {
	failure := Failure(provider, operation, goauth.ErrProvider)
	if len(code) <= 64 && !strings.ContainsFunc(code, func(character rune) bool {
		return !((character >= '0' && character <= '9') ||
			(character >= 'a' && character <= 'z') ||
			(character >= 'A' && character <= 'Z') ||
			character == '_' || character == '.' || character == '-')
	}) {
		failure.Code = code
	}
	return failure
}

func Present(values ...string) bool {
	for _, value := range values {
		if strings.TrimSpace(value) == "" {
			return false
		}
	}
	return true
}

func (client *Client) Do(ctx context.Context, operation, method, endpoint string, values url.Values) ([]byte, error) {
	return client.do(ctx, operation, method, endpoint, values, nil)
}

// JSONWithHeaders issues a form request carrying extra headers, such as an
// Authorization header, and decodes the response body into target under the
// same decoding contract as JSON.
func (client *Client) JSONWithHeaders(ctx context.Context, operation, method, endpoint string, values url.Values, headers map[string]string, target any) error {
	data, err := client.do(ctx, operation, method, endpoint, values, headers)
	return client.decode(operation, data, err, target)
}

func (client *Client) do(ctx context.Context, operation, method, endpoint string, values url.Values, headers map[string]string) ([]byte, error) {
	var body io.Reader
	if method == http.MethodGet {
		if encoded := values.Encode(); encoded != "" {
			endpoint += "?" + encoded
		}
	} else {
		body = strings.NewReader(values.Encode())
	}
	return client.request(ctx, operation, method, endpoint, "application/x-www-form-urlencoded", body, headers)
}

func (client *Client) request(ctx context.Context, operation, method, endpoint, contentType string, body io.Reader, headers map[string]string) ([]byte, error) {
	request, err := http.NewRequestWithContext(ctx, method, endpoint, body)
	if err != nil {
		return nil, Failure(client.provider, operation, goauth.ErrInvalidConfig)
	}
	request.Header.Set("Accept", "application/json")
	if method != http.MethodGet {
		request.Header.Set("Content-Type", contentType)
	}
	for name, value := range headers {
		request.Header.Set(name, value)
	}
	response, err := client.client.Do(request)
	if err != nil {
		kind := goauth.ErrTransport
		if errors.Is(err, context.Canceled) {
			kind = context.Canceled
		} else if errors.Is(err, context.DeadlineExceeded) {
			kind = context.DeadlineExceeded
		}
		return nil, Failure(client.provider, operation, kind)
	}
	defer response.Body.Close()
	var statusError error
	if response.StatusCode < 200 || response.StatusCode >= 300 {
		failure := Failure(client.provider, operation, goauth.ErrTransport)
		failure.StatusCode = response.StatusCode
		statusError = failure
	}
	data, err := io.ReadAll(io.LimitReader(response.Body, maxResponseBytes+1))
	if err != nil {
		kind := goauth.ErrTransport
		if errors.Is(err, context.Canceled) {
			kind = context.Canceled
		} else if errors.Is(err, context.DeadlineExceeded) {
			kind = context.DeadlineExceeded
		}
		return nil, Failure(client.provider, operation, kind)
	}
	if len(data) > maxResponseBytes {
		return nil, Failure(client.provider, operation, goauth.ErrResponse)
	}
	return data, statusError
}

// JSON issues a form request and decodes the response body into target. A JSON
// object or array body is decoded into target even for a failing HTTP status:
// callers must inspect the platform error fields in target before the returned
// error, so provider rejections keep their classified kind instead of
// degrading to ErrTransport.
func (client *Client) JSON(ctx context.Context, operation, method, endpoint string, values url.Values, target any) error {
	data, err := client.Do(ctx, operation, method, endpoint, values)
	return client.decode(operation, data, err, target)
}

// PostJSON issues a JSON request and decodes the response body into target
// under the same decoding contract as JSON.
func (client *Client) PostJSON(ctx context.Context, operation, endpoint string, payload, target any) error {
	body, err := json.Marshal(payload)
	if err != nil {
		return Failure(client.provider, operation, goauth.ErrInvalidConfig)
	}
	data, err := client.request(ctx, operation, http.MethodPost, endpoint, "application/json", bytes.NewReader(body), nil)
	return client.decode(operation, data, err, target)
}

func (client *Client) decode(operation string, data []byte, requestError error, target any) error {
	trimmed := bytes.TrimLeft(data, " \t\r\n")
	if len(trimmed) == 0 || (trimmed[0] != '{' && trimmed[0] != '[') || json.Unmarshal(data, target) != nil {
		if requestError != nil {
			return requestError
		}
		return Failure(client.provider, operation, goauth.ErrResponse)
	}
	return requestError
}
