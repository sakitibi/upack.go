package sencode

import (
	"crypto/ecdh"
	"crypto/ecdsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
)

// ==========================================
// 鍵のエクスポート / インポート処理
// ==========================================

type JWK struct {
	Kty string `json:"kty"`
	Crv string `json:"crv"`
	X   string `json:"x,omitempty"`
	Y   string `json:"y,omitempty"`
	D   string `json:"d,omitempty"`
	Ext bool   `json:"ext,omitempty"`
}

func ExportPublicKey(pub *ecdh.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func ImportPublicKey(base64Str string) (*ecdh.PublicKey, error) {
	der, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	key, err := x509.ParsePKIXPublicKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	switch pub := key.(type) {
	case *ecdh.PublicKey:
		return pub, nil
	case *ecdsa.PublicKey:
		return pub.ECDH()
	default:
		return nil, errors.New("not a supported public key type")
	}
}

func ExportPrivateKey(priv *ecdh.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	return base64.StdEncoding.EncodeToString(der), nil
}

func ImportPrivateKey(base64Str string) (*ecdh.PrivateKey, error) {
	der, err := base64.StdEncoding.DecodeString(base64Str)
	if err != nil {
		return nil, fmt.Errorf("failed to decode base64: %w", err)
	}

	key, err := x509.ParsePKCS8PrivateKey(der)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	switch p := key.(type) {
	case *ecdh.PrivateKey:
		return p, nil
	case *ecdsa.PrivateKey:
		return p.ECDH()
	default:
		return nil, errors.New("not a supported private key type")
	}
}

func ExportPublicKeyJWK(pub *ecdh.PublicKey) (string, error) {
	pubBytes := pub.Bytes() // 非圧縮フォーマット: 0x04 || X (32bytes) || Y (32bytes)
	if len(pubBytes) != 65 || pubBytes[0] != 0x04 {
		return "", errors.New("invalid uncompressed public key format")
	}

	xBytes := pubBytes[1:33]
	yBytes := pubBytes[33:65]

	jwk := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xBytes),
		Y:   base64.RawURLEncoding.EncodeToString(yBytes),
		Ext: true,
	}

	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ImportPublicKeyJWK(jwkStr string) (*ecdh.PublicKey, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		return nil, err
	}

	if jwk.Crv != "P-256" {
		return nil, fmt.Errorf("unsupported curve: %s", jwk.Crv)
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	if len(xBytes) != 32 || len(yBytes) != 32 {
		return nil, errors.New("invalid coordinate lengths for P-256")
	}

	// 非圧縮ポイント形式を構築: 0x04 || X || Y
	pubBytes := make([]byte, 65)
	pubBytes[0] = 0x04
	copy(pubBytes[1:33], xBytes)
	copy(pubBytes[33:65], yBytes)

	return ecdh.P256().NewPublicKey(pubBytes)
}

func ExportPrivateKeyJWK(priv *ecdh.PrivateKey) (string, error) {
	dBytes := priv.Bytes() // 32バイトの秘密鍵スカラー

	pubJWKStr, err := ExportPublicKeyJWK(priv.PublicKey())
	if err != nil {
		return "", err
	}

	var jwk JWK
	_ = json.Unmarshal([]byte(pubJWKStr), &jwk)
	jwk.D = base64.RawURLEncoding.EncodeToString(dBytes)

	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ImportPrivateKeyJWK(jwkStr string) (*ecdh.PrivateKey, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		return nil, err
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, err
	}

	return ecdh.P256().NewPrivateKey(dBytes)
}
