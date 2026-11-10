package certificates

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"

	libraryIO "github.com/pperminov/library/io"
)

func LoadRSAPublicKeyFromBytes(data []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*rsa.PublicKey)
	if !ok || pub.N.BitLen() < 2048 {
		return nil, errors.New("invalid or weak RSA public key")
	}

	return pub, nil
}
func LoadRSAPublicKeyFromPath(certPath string) (*rsa.PublicKey, error) {
	data, err := libraryIO.ReadFileToBytes(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading cert file: %w", err)
	}
	return LoadRSAPublicKeyFromBytes(data)
}

func LoadECPublicKeyFromBytes(data []byte) (*ecdsa.PublicKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("invalid certificate PEM")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parsing certificate: %w", err)
	}

	pub, ok := cert.PublicKey.(*ecdsa.PublicKey)
	if !ok || pub.Curve != elliptic.P256() {
		return nil, errors.New("invalid or unsupported EC public key")
	}

	return pub, nil
}

func LoadECPublicKeyFromPath(certPath string) (*ecdsa.PublicKey, error) {
	data, err := libraryIO.ReadFileToBytes(certPath)
	if err != nil {
		return nil, fmt.Errorf("reading cert file: %w", err)
	}
	return LoadECPublicKeyFromBytes(data)
}

func LoadRSAPrivateKeyFromBytes(data []byte) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("invalid private key PEM")
	}

	var priv *rsa.PrivateKey
	if key, err := x509.ParsePKCS1PrivateKey(block.Bytes); err == nil {
		priv = key
	} else if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := parsedKey.(*rsa.PrivateKey); ok {
			priv = k
		}
	}

	if priv == nil || priv.N.BitLen() < 2048 {
		return nil, errors.New("invalid or weak RSA private key")
	}

	return priv, nil
}

func LoadRSAPrivateKeyFromPath(keyPath string) (*rsa.PrivateKey, error) {
	data, err := libraryIO.ReadFileToBytes(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return LoadRSAPrivateKeyFromBytes(data)
}

func LoadECPrivateKeyFromBytes(data []byte) (*ecdsa.PrivateKey, error) {
	block, _ := pem.Decode(data)
	if block == nil || !strings.HasSuffix(block.Type, "PRIVATE KEY") {
		return nil, errors.New("invalid private key PEM")
	}

	var priv *ecdsa.PrivateKey
	if key, err := x509.ParseECPrivateKey(block.Bytes); err == nil {
		priv = key
	} else if parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes); err == nil {
		if k, ok := parsedKey.(*ecdsa.PrivateKey); ok {
			priv = k
		}
	}

	if priv == nil || priv.Curve != elliptic.P256() {
		return nil, errors.New("invalid or unsupported EC private key")
	}

	return priv, nil
}

func LoadECPrivateKeyFromPath(keyPath string) (*ecdsa.PrivateKey, error) {
	data, err := libraryIO.ReadFileToBytes(keyPath)
	if err != nil {
		return nil, fmt.Errorf("reading key file: %w", err)
	}
	return LoadECPrivateKeyFromBytes(data)
}
