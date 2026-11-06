package alipay

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
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

func keys(t *testing.T) (Config, *rsa.PrivateKey, *rsa.PrivateKey) {
	t.Helper()
	application, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	gateway, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	publicDER, err := x509.MarshalPKIXPublicKey(&gateway.PublicKey)
	if err != nil {
		t.Fatal(err)
	}
	return Config{
		AppID:              "app",
		PrivateKeyPEM:      string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(application)})),
		AlipayPublicKeyPEM: string(pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: publicDER})),
	}, application, gateway
}

func signed(t *testing.T, key *rsa.PrivateKey, root, payload string) string {
	t.Helper()
	digest := sha256.Sum256([]byte(payload))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Error(err)
		return "{}"
	}
	return fmt.Sprintf(`{"%s":%s,"sign":"%s"}`, root, payload, base64.StdEncoding.EncodeToString(signature))
}

func TestExchangeAndRequestSignature(t *testing.T) {
	config, application, gateway := keys(t)
	calls := 0
	config.FetchProfile = true
	config.HTTPClient = testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Method != http.MethodPost || request.Host != "openapi.alipay.com" ||
			request.URL.Path != "/gateway.do" || request.Header.Get("Content-Type") != "application/x-www-form-urlencoded" {
			t.Error("unexpected gateway request")
		}
		if err := request.ParseForm(); err != nil {
			t.Error(err)
		}
		params := request.PostForm
		stamp, err := time.ParseInLocation("2006-01-02 15:04:05", params.Get("timestamp"), time.FixedZone("CST", 8*60*60))
		if err != nil || time.Since(stamp) > 5*time.Second || time.Until(stamp) > time.Second {
			t.Error("timestamp must use GMT+8")
		}
		var canonical, payload, root string
		switch params.Get("method") {
		case "alipay.system.oauth.token":
			if len(params) != 10 || params.Get("code") != "code+ /" || params.Get("grant_type") != "authorization_code" {
				t.Error("invalid token parameters")
			}
			canonical = "app_id=app&charset=utf-8&code=code+ /&format=json&grant_type=authorization_code&method=alipay.system.oauth.token&sign_type=RSA2&timestamp=" + params.Get("timestamp") + "&version=1.0"
			root = "alipay_system_oauth_token_response"
			payload = `{ "access_token":"token", "expires_in":"7200", "open_id":"person", "union_id":"union", "extra":{"text":"} \u4e2d \/"}}`
		case "alipay.user.info.share":
			if len(params) != 9 || params.Get("auth_token") != "token" || params.Get("access_token") != "" {
				t.Error("invalid profile parameters")
			}
			canonical = "app_id=app&auth_token=token&charset=utf-8&format=json&method=alipay.user.info.share&sign_type=RSA2&timestamp=" + params.Get("timestamp") + "&version=1.0"
			root = "alipay_user_info_share_response"
			payload = `{"code":"10000","open_id":"person","nick_name":"测试","user_name":"授权姓名","email":"person@example.com","avatar":"https:\/\/example.com\/avatar"}`
		default:
			t.Errorf("unexpected method %q", params.Get("method"))
			writer.WriteHeader(400)
			return
		}
		digest := sha256.Sum256([]byte(canonical))
		signature, err := base64.StdEncoding.DecodeString(params.Get("sign"))
		if err != nil || rsa.VerifyPKCS1v15(&application.PublicKey, crypto.SHA256, digest[:], signature) != nil {
			t.Error("invalid application signature")
		}
		fmt.Fprint(writer, signed(t, gateway, root, payload))
	})
	provider, err := New(config)
	if err != nil {
		t.Fatal(err)
	}
	identity, err := provider.Exchange(context.Background(), "code+ /")
	if err != nil || identity.Provider != goauth.Alipay || identity.AppID != "app" ||
		identity.ID != "person" || identity.SubjectType != goauth.OpenID ||
		identity.UnionID != "union" || identity.Nickname != "测试" || calls != 2 {
		t.Fatalf("identity=%+v error=%v calls=%d", identity, err, calls)
	}
	if identity.Name != "授权姓名" || identity.Email != "person@example.com" ||
		identity.Raw["open_id"] != "person" || identity.TokenResponse["access_token"] != "token" ||
		identity.TokenResponse["expires_in"] != "7200" || identity.TokenResponse["extra"] == nil ||
		identity.TokenResponse["sign"] != nil || identity.Raw["alipay_user_info_share_response"] != nil {
		t.Fatalf("incomplete or incorrectly wrapped user: %+v", identity)
	}
}

func TestResponseValidation(t *testing.T) {
	config, application, gateway := keys(t)
	root := "alipay_system_oauth_token_response"
	payload := `{"access_token":"token","expires_in":"7200","open_id":"person"}`
	valid := signed(t, gateway, root, payload)
	for _, scenario := range []struct {
		name string
		body string
		want error
	}{
		{"tampered", strings.Replace(valid, `"person"`, `"attacker"`, 1), goauth.ErrSignature},
		{"wrong public key", signed(t, application, root, payload), goauth.ErrSignature},
		{"unsigned success", fmt.Sprintf(`{"%s":%s}`, root, payload), goauth.ErrSignature},
		{"invalid base64", fmt.Sprintf(`{"%s":%s,"sign":"%%"}`, root, payload), goauth.ErrSignature},
		{"wrong sign type", strings.TrimSuffix(valid, "}") + `,"sign_type":"RSA"}`, goauth.ErrSignature},
		{"duplicate signature", strings.TrimSuffix(valid, "}") + `,"sign":"other"}`, goauth.ErrResponse},
		{"duplicate response", strings.TrimSuffix(valid, "}") + `,"` + root + `":` + payload + `}`, goauth.ErrResponse},
		{"ambiguous roots", strings.TrimSuffix(valid, "}") + `,"error_response":{"code":"40004"}}`, goauth.ErrResponse},
		{"unsigned error", `{"error_response":{"code":"40004","sub_msg":"secret token"}}`, goauth.ErrProvider},
		{"signed error", signed(t, gateway, "error_response", `{"code":"40004"}`), goauth.ErrProvider},
		{"invalid signed error", signed(t, application, "error_response", `{"code":"40004"}`), goauth.ErrSignature},
		{"business error", signed(t, gateway, root, `{"code":"40004"}`), goauth.ErrProvider},
		{"empty token", signed(t, gateway, root, `{"open_id":"person","expires_in":"7200"}`), goauth.ErrResponse},
		{"empty identity", signed(t, gateway, root, `{"access_token":"token","expires_in":"7200"}`), goauth.ErrResponse},
		{"no identity fallback", signed(t, gateway, root, `{"access_token":"token","expires_in":"7200","user_id":"legacy"}`), goauth.ErrResponse},
		{"expired", signed(t, gateway, root, `{"access_token":"token","expires_in":"0","open_id":"person"}`), goauth.ErrResponse},
		{"empty object", `{}`, goauth.ErrResponse},
		{"trailing JSON", valid + `{}`, goauth.ErrResponse},
		{"malformed", `{`, goauth.ErrResponse},
		{"null", `null`, goauth.ErrResponse},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			current := config
			current.HTTPClient = testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprint(writer, scenario.body)
			})
			provider, err := New(current)
			if err != nil {
				t.Fatal(err)
			}
			identity, err := provider.Exchange(context.Background(), "code")
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(identity, goauth.User{}) {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
			if strings.Contains(err.Error(), "secret token") {
				t.Fatal("platform message leaked")
			}
		})
	}
}

func TestLegacyIdentityAndProfileMismatch(t *testing.T) {
	config, _, gateway := keys(t)
	config.SubjectType = goauth.UserID
	for _, fetchProfile := range []bool{false, true} {
		t.Run(fmt.Sprint(fetchProfile), func(t *testing.T) {
			current := config
			current.FetchProfile = fetchProfile
			calls := 0
			current.HTTPClient = testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				calls++
				if err := request.ParseForm(); err != nil {
					t.Error(err)
				}
				if request.PostForm.Get("method") == "alipay.system.oauth.token" {
					fmt.Fprint(writer, signed(t, gateway, "alipay_system_oauth_token_response",
						`{"access_token":"token","expires_in":7200,"user_id":"legacy"}`))
				} else {
					fmt.Fprint(writer, signed(t, gateway, "alipay_user_info_share_response",
						`{"code":"10000","user_id":"other"}`))
				}
			})
			provider, err := New(current)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := provider.Exchange(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
				t.Fatalf("empty code: %v", err)
			}
			identity, err := provider.Exchange(context.Background(), "code")
			if fetchProfile {
				if !errors.Is(err, goauth.ErrIdentityMismatch) || !reflect.DeepEqual(identity, goauth.User{}) {
					t.Fatalf("identity=%+v error=%v", identity, err)
				}
			} else if err != nil || identity.ID != "legacy" || identity.SubjectType != goauth.UserID || len(identity.Raw) != 0 {
				t.Fatalf("identity=%+v error=%v", identity, err)
			}
		})
	}
}

func TestConfigurationAndKeyFormats(t *testing.T) {
	config, application, gateway := keys(t)
	privateDER, err := x509.MarshalPKCS8PrivateKey(application)
	if err != nil {
		t.Fatal(err)
	}
	alternative := config
	alternative.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privateDER}))
	alternative.AlipayPublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&gateway.PublicKey)}))
	if _, err := New(alternative); err != nil {
		t.Fatal(err)
	}
	weak, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		t.Fatal(err)
	}
	otherKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	otherDER, err := x509.MarshalPKCS8PrivateKey(otherKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, mutate := range []func(*Config){
		func(config *Config) { config.AppID = "" },
		func(config *Config) { config.PrivateKeyPEM = "" },
		func(config *Config) { config.AlipayPublicKeyPEM = "" },
		func(config *Config) { config.SubjectType = "unsupported" },
		func(config *Config) { config.PrivateKeyPEM += "extra content" },
		func(config *Config) {
			config.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(weak)}))
		},
		func(config *Config) {
			config.AlipayPublicKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "RSA PUBLIC KEY", Bytes: x509.MarshalPKCS1PublicKey(&weak.PublicKey)}))
		},
		func(config *Config) {
			config.PrivateKeyPEM = string(pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: otherDER}))
		},
	} {
		current := config
		mutate(&current)
		if _, err := New(current); !errors.Is(err, goauth.ErrInvalidConfig) {
			t.Fatalf("invalid configuration: %v", err)
		}
	}
}
