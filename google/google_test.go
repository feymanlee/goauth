package google

import (
	"context"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"reflect"
	"testing"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/testutil"
)

func key(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	generated, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	return generated
}

func jwks(t *testing.T, kid string, key *rsa.PublicKey) string {
	t.Helper()
	return fmt.Sprintf(`{"keys":[{"kty":"RSA","alg":"RS256","use":"sig","kid":%q,"n":%q,"e":%q}]}`,
		kid,
		base64.RawURLEncoding.EncodeToString(key.N.Bytes()),
		base64.RawURLEncoding.EncodeToString(big.NewInt(int64(key.E)).Bytes()))
}

func token(t *testing.T, key *rsa.PrivateKey, kid, algorithm, claims string) string {
	t.Helper()
	segment := func(value string) string {
		return base64.RawURLEncoding.EncodeToString([]byte(value))
	}
	signingInput := segment(fmt.Sprintf(`{"alg":%q,"kid":%q}`, algorithm, kid)) + "." + segment(claims)
	digest := sha256.Sum256([]byte(signingInput))
	signature, err := rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, digest[:])
	if err != nil {
		t.Fatal(err)
	}
	return signingInput + "." + base64.RawURLEncoding.EncodeToString(signature)
}

func claims(issuer, audience, subject string, expiresAt int64, emailVerified bool) string {
	return fmt.Sprintf(`{"iss":%q,"aud":%q,"sub":%q,"exp":%d,"email":"person@example.com","email_verified":%t,"name":"Test User","picture":"https://example.com/picture"}`,
		issuer, audience, subject, expiresAt, emailVerified)
}

func TestVerify(t *testing.T) {
	signing := key(t)
	certificates := jwks(t, "primary", &signing.PublicKey)
	valid := token(t, signing, "primary", "RS256",
		claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true))
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
		if request.Host != "www.googleapis.com" || request.URL.Path != "/oauth2/v3/certs" {
			t.Errorf("unexpected request: %s%s", request.Host, request.URL.Path)
		}
		fmt.Fprint(writer, certificates)
	})
	provider, err := New(Config{ClientID: "client", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	user, err := provider.Verify(context.Background(), valid)
	if err != nil || user.Provider != goauth.Google || user.AppID != "client" ||
		user.ID != "1234567890" || user.SubjectType != goauth.UserID ||
		user.Name != "Test User" || user.Email != "person@example.com" ||
		user.Avatar != "https://example.com/picture" || calls != 1 {
		t.Fatalf("user=%+v error=%v calls=%d", user, err, calls)
	}
	if user.Raw["sub"] != "1234567890" {
		t.Fatalf("raw claims missing subject: %+v", user.Raw)
	}
	if _, valid := user.Raw["exp"].(json.Number); !valid {
		t.Fatalf("exp claim lost number precision: %+v", user.Raw)
	}
	if user.TokenResponse["id_token"] != valid || len(user.TokenResponse) != 1 || user.UnionID != "" {
		t.Fatalf("unexpected token response: %+v", user.TokenResponse)
	}
}

func TestVerifyVariants(t *testing.T) {
	for _, scenario := range []struct {
		name   string
		claims func() string
		email  string
	}{
		{"legacy issuer", func() string {
			return claims("accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true)
		}, "person@example.com"},
		{"unverified email", func() string {
			return claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), false)
		}, ""},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			signing := key(t)
			certificates := jwks(t, "primary", &signing.PublicKey)
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprint(writer, certificates)
			})
			provider, err := New(Config{ClientID: "client", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			user, err := provider.Verify(context.Background(), token(t, signing, "primary", "RS256", scenario.claims()))
			if err != nil || user.Email != scenario.email {
				t.Fatalf("user=%+v error=%v", user, err)
			}
		})
	}
}

func TestVerifyFailures(t *testing.T) {
	for _, scenario := range []struct {
		name      string
		claims    string
		keyID     string
		algorithm string
		want      error
	}{
		{"wrong audience", claims("https://accounts.google.com", "other", "1234567890", time.Now().Add(time.Hour).Unix(), true), "primary", "RS256", goauth.ErrIdentityMismatch},
		{"expired", claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(-time.Minute).Unix(), true), "primary", "RS256", goauth.ErrInvalidCredential},
		{"missing expiry", `{"iss":"https://accounts.google.com","aud":"client","sub":"1234567890"}`, "primary", "RS256", goauth.ErrResponse},
		{"wrong issuer", claims("https://accounts.example.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true), "primary", "RS256", goauth.ErrResponse},
		{"missing subject", claims("https://accounts.google.com", "client", "", time.Now().Add(time.Hour).Unix(), true), "primary", "RS256", goauth.ErrResponse},
		{"malformed expiry", `{"iss":"https://accounts.google.com","aud":"client","sub":"1234567890","exp":"soon"}`, "primary", "RS256", goauth.ErrResponse},
		{"forged signature", claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true), "primary", "RS256", goauth.ErrSignature},
		{"retired key", claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true), "retired", "RS256", goauth.ErrSignature},
		{"unsigned algorithm", claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true), "primary", "HS256", goauth.ErrSignature},
	} {
		t.Run(scenario.name, func(t *testing.T) {
			signing := key(t)
			rogue := key(t)
			certificates := jwks(t, "primary", &signing.PublicKey)
			client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
				fmt.Fprint(writer, certificates)
			})
			provider, err := New(Config{ClientID: "client", HTTPClient: client})
			if err != nil {
				t.Fatal(err)
			}
			signKey := signing
			if scenario.name == "forged signature" {
				signKey = rogue
			}
			user, err := provider.Verify(context.Background(), token(t, signKey, scenario.keyID, scenario.algorithm, scenario.claims))
			if !errors.Is(err, scenario.want) || !reflect.DeepEqual(user, goauth.User{}) {
				t.Fatalf("user=%+v error=%v", user, err)
			}
		})
	}
}

func TestMalformedTokenAndCertificateFailures(t *testing.T) {
	signing := key(t)
	certificates := jwks(t, "primary", &signing.PublicKey)
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		fmt.Fprint(writer, certificates)
	})
	provider, err := New(Config{ClientID: "client", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	for _, malformed := range []string{"abc.def", "a.b.c.d", "!!!.???.***", "."} {
		if _, err := provider.Verify(context.Background(), malformed); !errors.Is(err, goauth.ErrResponse) {
			t.Fatalf("malformed %q: %v", malformed, err)
		}
	}
	unreachable := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(http.StatusInternalServerError)
	})
	broken, err := New(Config{ClientID: "client", HTTPClient: unreachable})
	if err != nil {
		t.Fatal(err)
	}
	valid := token(t, signing, "primary", "RS256",
		claims("https://accounts.google.com", "client", "1234567890", time.Now().Add(time.Hour).Unix(), true))
	if _, err := broken.Verify(context.Background(), valid); !errors.Is(err, goauth.ErrTransport) {
		t.Fatalf("certificate failure: %v", err)
	}
}

func TestValidation(t *testing.T) {
	if _, err := New(Config{}); !errors.Is(err, goauth.ErrInvalidConfig) {
		t.Fatal(err)
	}
	calls := 0
	client := testutil.Client(t, func(writer http.ResponseWriter, request *http.Request) {
		calls++
	})
	provider, err := New(Config{ClientID: "client", HTTPClient: client})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := provider.Verify(context.Background(), " "); !errors.Is(err, goauth.ErrInvalidCredential) || calls != 0 {
		t.Fatalf("empty token: %v calls=%d", err, calls)
	}
}
