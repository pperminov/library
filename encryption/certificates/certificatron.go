package certificates

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"

	libraryErrors "github.com/pperminov/library/errors"
)

type Certificatron struct {
	cert  *rsa.PublicKey
	key   *rsa.PrivateKey
	label []byte
}

func NewCertificatron(keyPath, certPath, label string) (crtftn Certificatron, err error) {
	if certPath != "" {
		crtftn.cert, err = LoadRSAPublicKeyFromPath(certPath)
		if err != nil {
			return
		}
	}
	if keyPath != "" {
		crtftn.key, err = LoadRSAPrivateKeyFromPath(keyPath)
		if err != nil {
			return
		}
	}
	crtftn.label = []byte(label)
	return
}

func (c *Certificatron) Encrypt(msg []byte) ([]byte, error) {
	if c.cert == nil {
		return nil, libraryErrors.NewError("no certificate available. Encryption is not possible")
	}
	hash := sha256.New()
	return rsa.EncryptOAEP(hash, rand.Reader, c.cert, msg, c.label)
}

func (c *Certificatron) Decrypt(ciphertext []byte) ([]byte, error) {
	if c.cert == nil {
		return nil, libraryErrors.NewError("no key available. Decryption is not possible")
	}
	hash := sha256.New()
	return rsa.DecryptOAEP(hash, rand.Reader, c.key, ciphertext, c.label)
}
