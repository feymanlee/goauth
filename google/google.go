package google

import (
	"bytes"
	"context"
	"crypto"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"math/big"
	"net/http"
	"strings"
	"time"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

const certificatesEndpoint = "https://www.googleapis.com/oauth2/v3/certs"

type Config struct {
	ClientID string
	// HTTPClient supplies the client used for certificate requests. A
	// non-positive timeout falls back to 10s per request and the redirect
	// policy is always replaced: certificate responses must not redirect.
	HTTPClient *http.Client
}

type Provider struct {
	clientID string
	http     *httpx.Client
}

var _ goauth.TokenVerifier = (*Provider)(nil)

func New(config Config) (*Provider, error) {
	if !httpx.Present(config.ClientID) {
		return nil, httpx.Failure(goauth.Google, "configure", goauth.ErrInvalidConfig)
	}
	return &Provider{
		clientID: config.ClientID, http: httpx.New(goauth.Google, config.HTTPClient),
	}, nil
}

func (provider *Provider) Verify(ctx context.Context, idToken string) (goauth.User, error) {
	if !httpx.Present(idToken) {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrInvalidCredential)
	}
	decoded, err := decodeToken(idToken)
	if err != nil {
		return goauth.User{}, err
	}
	if decoded.header.Algorithm != "RS256" {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
	}
	key, err := provider.signingKey(ctx, decoded.header.KeyID)
	if err != nil {
		return goauth.User{}, err
	}
	digest := sha256.Sum256(decoded.signingInput)
	if rsa.VerifyPKCS1v15(key, crypto.SHA256, digest[:], decoded.signature) != nil {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
	}
	if decoded.claims.Issuer != "https://accounts.google.com" && decoded.claims.Issuer != "accounts.google.com" {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrResponse)
	}
	if decoded.claims.Audience != provider.clientID {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrIdentityMismatch)
	}
	if decoded.claims.ExpiresAt == 0 {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrResponse)
	}
	if decoded.claims.ExpiresAt <= time.Now().Unix() {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrInvalidCredential)
	}
	if !httpx.Present(decoded.claims.Subject) {
		return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrResponse)
	}
	user := goauth.User{
		Provider: goauth.Google, AppID: provider.clientID,
		ID: decoded.claims.Subject, SubjectType: goauth.UserID,
		Raw: make(map[string]any), TokenResponse: map[string]any{"id_token": idToken},
	}
	user.Name = decoded.claims.Name
	user.Avatar = decoded.claims.Picture
	if decoded.claims.EmailVerified {
		user.Email = decoded.claims.Email
	}
	if len(decoded.payload) != 0 {
		decoder := json.NewDecoder(bytes.NewReader(decoded.payload))
		decoder.UseNumber()
		if decoder.Decode(&user.Raw) != nil {
			return goauth.User{}, httpx.Failure(goauth.Google, "verify", goauth.ErrResponse)
		}
	}
	return user, nil
}

type tokenHeader struct {
	Algorithm string `json:"alg"`
	KeyID     string `json:"kid"`
}

type tokenClaims struct {
	Issuer        string `json:"iss"`
	Audience      string `json:"aud"`
	Subject       string `json:"sub"`
	ExpiresAt     int64  `json:"exp"`
	Email         string `json:"email"`
	EmailVerified bool   `json:"email_verified"`
	Name          string `json:"name"`
	Picture       string `json:"picture"`
}

type encodedToken struct {
	header       tokenHeader
	claims       tokenClaims
	payload      []byte
	signingInput []byte
	signature    []byte
}

func decodeToken(idToken string) (encodedToken, error) {
	invalid := httpx.Failure(goauth.Google, "verify", goauth.ErrResponse)
	parts := strings.Split(idToken, ".")
	if len(parts) != 3 {
		return encodedToken{}, invalid
	}
	signingInput := []byte(parts[0] + "." + parts[1])
	headerBytes, err := base64.RawURLEncoding.DecodeString(parts[0])
	if err != nil {
		return encodedToken{}, invalid
	}
	payload, err := base64.RawURLEncoding.DecodeString(parts[1])
	if err != nil {
		return encodedToken{}, invalid
	}
	signature, err := base64.RawURLEncoding.DecodeString(parts[2])
	if err != nil {
		return encodedToken{}, invalid
	}
	var header tokenHeader
	if json.Unmarshal(headerBytes, &header) != nil {
		return encodedToken{}, invalid
	}
	var claims tokenClaims
	if json.Unmarshal(payload, &claims) != nil {
		return encodedToken{}, invalid
	}
	return encodedToken{header: header, claims: claims, payload: payload, signingInput: signingInput, signature: signature}, nil
}

func (provider *Provider) signingKey(ctx context.Context, keyID string) (*rsa.PublicKey, error) {
	var certificates struct {
		Keys []struct {
			KeyType  string `json:"kty"`
			KeyID    string `json:"kid"`
			Modulus  string `json:"n"`
			Exponent string `json:"e"`
		} `json:"keys"`
	}
	if err := provider.http.JSON(ctx, "certificates", http.MethodGet, certificatesEndpoint, nil, &certificates); err != nil {
		return nil, err
	}
	for _, key := range certificates.Keys {
		if key.KeyID != keyID || key.KeyType != "RSA" {
			continue
		}
		modulus, err := base64.RawURLEncoding.DecodeString(key.Modulus)
		if err != nil {
			return nil, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
		}
		exponent, err := base64.RawURLEncoding.DecodeString(key.Exponent)
		if err != nil {
			return nil, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
		}
		if len(exponent) > 8 {
			return nil, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
		}
		power := 0
		for _, digit := range exponent {
			power = power<<8 | int(digit)
		}
		return &rsa.PublicKey{N: new(big.Int).SetBytes(modulus), E: power}, nil
	}
	return nil, httpx.Failure(goauth.Google, "verify", goauth.ErrSignature)
}
