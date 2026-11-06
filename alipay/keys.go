package alipay

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"strings"

	"github.com/feymanlee/goauth"
	"github.com/feymanlee/goauth/internal/httpx"
)

func parsePrivateKey(encoded string) (*rsa.PrivateKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, invalidConfig()
	}
	var privateKey *rsa.PrivateKey
	switch block.Type {
	case "RSA PRIVATE KEY":
		parsed, err := x509.ParsePKCS1PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidConfig()
		}
		privateKey = parsed
	case "PRIVATE KEY":
		parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, invalidConfig()
		}
		var valid bool
		privateKey, valid = parsed.(*rsa.PrivateKey)
		if !valid {
			return nil, invalidConfig()
		}
	default:
		return nil, invalidConfig()
	}
	if privateKey.N.BitLen() < 2048 || privateKey.Validate() != nil {
		return nil, invalidConfig()
	}
	privateKey.Precompute()
	return privateKey, nil
}

func parsePublicKey(encoded string) (*rsa.PublicKey, error) {
	block, rest := pem.Decode([]byte(encoded))
	if block == nil || strings.TrimSpace(string(rest)) != "" {
		return nil, invalidConfig()
	}
	var publicKey *rsa.PublicKey
	switch block.Type {
	case "RSA PUBLIC KEY":
		parsed, err := x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, invalidConfig()
		}
		publicKey = parsed
	case "PUBLIC KEY":
		parsed, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, invalidConfig()
		}
		var valid bool
		publicKey, valid = parsed.(*rsa.PublicKey)
		if !valid {
			return nil, invalidConfig()
		}
	default:
		return nil, invalidConfig()
	}
	if publicKey.N.BitLen() < 2048 || publicKey.E < 3 || publicKey.E%2 == 0 {
		return nil, invalidConfig()
	}
	return publicKey, nil
}

func invalidConfig() error {
	return httpx.Failure(goauth.Alipay, "configure", goauth.ErrInvalidConfig)
}
