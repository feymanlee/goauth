package alipay

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

func (provider *Provider) call(ctx context.Context, operation, method string, values url.Values, target any) error {
	values.Set("app_id", provider.appID)
	values.Set("method", method)
	values.Set("format", "json")
	values.Set("charset", "utf-8")
	values.Set("sign_type", "RSA2")
	values.Set("timestamp", time.Now().In(time.FixedZone("CST", 8*60*60)).Format("2006-01-02 15:04:05"))
	values.Set("version", "1.0")
	digest := sha256.Sum256([]byte(signingContent(values)))
	signature, err := rsa.SignPKCS1v15(rand.Reader, provider.privateKey, crypto.SHA256, digest[:])
	if err != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrInvalidConfig)
	}
	values.Set("sign", base64.StdEncoding.EncodeToString(signature))
	data, err := provider.http.Do(ctx, operation, http.MethodPost, "https://openapi.alipay.com/gateway.do", values)
	if err != nil {
		return err
	}
	envelope, err := decodeEnvelope(data)
	if err != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
	}
	payload, present := envelope[strings.ReplaceAll(method, ".", "_")+"_response"]
	errorPayload, hasError := envelope["error_response"]
	if present && hasError {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
	}
	if !present {
		if !hasError {
			return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
		}
		payload = errorPayload
	}
	var status struct {
		Code string `json:"code"`
	}
	if !strings.HasPrefix(strings.TrimSpace(string(payload)), "{") || json.Unmarshal(payload, &status) != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
	}
	isFailure := status.Code != "" && status.Code != "10000"
	if hasError && !isFailure {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
	}
	if _, signed := envelope["sign"]; !signed && isFailure {
		return httpx.Rejected(goauth.Alipay, operation, status.Code)
	}
	var sign string
	if json.Unmarshal(envelope["sign"], &sign) != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrSignature)
	}
	if encodedType, exists := envelope["sign_type"]; exists {
		var signType string
		if json.Unmarshal(encodedType, &signType) != nil || signType != "RSA2" {
			return httpx.Failure(goauth.Alipay, operation, goauth.ErrSignature)
		}
	}
	decoded, err := base64.StdEncoding.DecodeString(sign)
	if err != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrSignature)
	}
	responseDigest := sha256.Sum256(payload)
	if rsa.VerifyPKCS1v15(provider.publicKey, crypto.SHA256, responseDigest[:], decoded) != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrSignature)
	}
	if isFailure {
		return httpx.Rejected(goauth.Alipay, operation, status.Code)
	}
	if json.Unmarshal(payload, target) != nil {
		return httpx.Failure(goauth.Alipay, operation, goauth.ErrResponse)
	}
	return nil
}

func decodeEnvelope(data []byte) (map[string]json.RawMessage, error) {
	decoder := json.NewDecoder(bytes.NewReader(data))
	start, err := decoder.Token()
	if err != nil || start != json.Delim('{') {
		return nil, goauth.ErrResponse
	}
	envelope := make(map[string]json.RawMessage)
	for decoder.More() {
		token, err := decoder.Token()
		if err != nil {
			return nil, goauth.ErrResponse
		}
		key, valid := token.(string)
		if !valid {
			return nil, goauth.ErrResponse
		}
		if _, duplicate := envelope[key]; duplicate {
			return nil, goauth.ErrResponse
		}
		var raw json.RawMessage
		if decoder.Decode(&raw) != nil {
			return nil, goauth.ErrResponse
		}
		envelope[key] = raw
	}
	end, err := decoder.Token()
	if err != nil || end != json.Delim('}') {
		return nil, goauth.ErrResponse
	}
	if _, err := decoder.Token(); err != io.EOF {
		return nil, goauth.ErrResponse
	}
	return envelope, nil
}

func signingContent(values url.Values) string {
	keys := make([]string, 0, len(values))
	for key := range values {
		if key != "sign" && values.Get(key) != "" {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	parts := make([]string, 0, len(keys))
	for _, key := range keys {
		parts = append(parts, key+"="+values.Get(key))
	}
	return strings.Join(parts, "&")
}
