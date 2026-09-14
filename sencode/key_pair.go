package sencode

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
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

func ExportPublicKey(pub *ecdsa.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}
	block := &pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func ImportPublicKey(pemStr string) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	key, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKIX public key: %w", err)
	}

	pubKey, ok := key.(*ecdsa.PublicKey)
	if !ok {
		return nil, errors.New("not an ECDSA public key")
	}
	return pubKey, nil
}

func ExportPrivateKey(priv *ecdsa.PrivateKey) (string, error) {
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return "", fmt.Errorf("failed to marshal private key: %w", err)
	}
	block := &pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}
	return string(pem.EncodeToMemory(block)), nil
}

func ImportPrivateKey(pemStr string) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(pemStr))
	if block == nil {
		return nil, errors.New("invalid PEM data")
	}

	key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS8 private key: %w", err)
	}

	privKey, ok := key.(*ecdsa.PrivateKey)
	if !ok {
		return nil, errors.New("not an ECDSA private key")
	}
	return privKey, nil
}

// --- JWK (JSON Web Key) 補助用関数 ---

func ExportPublicKeyJWK(pub *ecdsa.PublicKey) (string, error) {
	xBytes := pub.X.Bytes()
	yBytes := pub.Y.Bytes()

	xPad := make([]byte, 32)
	yPad := make([]byte, 32)
	copy(xPad[32-len(xBytes):], xBytes)
	copy(yPad[32-len(yBytes):], yBytes)

	jwk := JWK{
		Kty: "EC",
		Crv: "P-256",
		X:   base64.RawURLEncoding.EncodeToString(xPad),
		Y:   base64.RawURLEncoding.EncodeToString(yPad),
		Ext: true,
	}

	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ImportPublicKeyJWK(jwkStr string) (*ecdsa.PublicKey, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		return nil, err
	}

	xBytes, err := base64.RawURLEncoding.DecodeString(jwk.X)
	if err != nil {
		return nil, err
	}
	yBytes, err := base64.RawURLEncoding.DecodeString(jwk.Y)
	if err != nil {
		return nil, err
	}

	pub := &ecdsa.PublicKey{
		Curve: elliptic.P256(),
		X:     new(big.Int).SetBytes(xBytes),
		Y:     new(big.Int).SetBytes(yBytes),
	}
	return pub, nil
}

func ExportPrivateKeyJWK(priv *ecdsa.PrivateKey) (string, error) {
	dBytes := priv.D.Bytes()
	dPad := make([]byte, 32)
	copy(dPad[32-len(dBytes):], dBytes)

	pubJWKStr, err := ExportPublicKeyJWK(&priv.PublicKey)
	if err != nil {
		return "", err
	}

	var jwk JWK
	_ = json.Unmarshal([]byte(pubJWKStr), &jwk)
	jwk.D = base64.RawURLEncoding.EncodeToString(dPad)

	b, err := json.Marshal(jwk)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func ImportPrivateKeyJWK(jwkStr string) (*ecdsa.PrivateKey, error) {
	var jwk JWK
	if err := json.Unmarshal([]byte(jwkStr), &jwk); err != nil {
		return nil, err
	}

	pub, err := ImportPublicKeyJWK(jwkStr)
	if err != nil {
		return nil, err
	}

	dBytes, err := base64.RawURLEncoding.DecodeString(jwk.D)
	if err != nil {
		return nil, err
	}

	priv := &ecdsa.PrivateKey{
		PublicKey: *pub,
		D:         new(big.Int).SetBytes(dBytes),
	}
	return priv, nil
}
