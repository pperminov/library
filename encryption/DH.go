package libraryEncryption

import (
	"bytes"
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"io"

	"golang.org/x/crypto/hkdf"

	libraryErrors "github.com/pperminov/library/errors"
	libraryNetwork "github.com/pperminov/library/network"
)

func GetECDHKeysFromConnectionWithKeyDerivation(conn libraryNetwork.GenericConnection) (sendKey, recvKey []byte, err error) {
	secret, pubKeyBytes, otherPubKeyBytes, err := getECDHKeysFromConnection(conn)
	if err != nil {
		return nil, nil, err
	}
	return deriveECDHKeys(secret, pubKeyBytes, otherPubKeyBytes)

}

func GetECDHKeysFromConnection(conn libraryNetwork.GenericConnection) (secret []byte, err error) {
	secret, _, _, err = getECDHKeysFromConnection(conn)
	return secret, err
}

func getECDHKeysFromConnection(conn libraryNetwork.GenericConnection) (secret, pub1, pub2 []byte, err error) {
	wrap := libraryErrors.PartWrapError("GetECDHKeysFromConnection")

	curve := ecdh.P521()

	privKey, err := curve.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, nil, wrap(err)
	}

	pubKeyBytes := privKey.PublicKey().Bytes()
	pubKeySize := len(pubKeyBytes)
	if _, err := conn.Write(pubKeyBytes); err != nil {
		return nil, nil, nil, wrap(err)
	}

	otherPubKeyBytes := make([]byte, pubKeySize)
	if _, err := io.ReadFull(conn, otherPubKeyBytes); err != nil {
		return nil, nil, nil, wrap(err)
	}

	otherPubKey, err := curve.NewPublicKey(otherPubKeyBytes)
	if err != nil {
		return nil, nil, nil, wrap(err)
	}

	sharedSecret, err := privKey.ECDH(otherPubKey)
	if err != nil {
		return nil, nil, nil, wrap(err)
	}

	return sharedSecret, pubKeyBytes, otherPubKeyBytes, nil
}

func deriveECDHKeys(sharedSecret, pubA, pubB []byte) (sendKey, recvKey []byte, err error) {
	salt := []byte("ECDH-HKDF-salt")
	infoSend := []byte("key:initiator")
	infoRecv := []byte("key:responder")

	if bytes.Compare(pubA, pubB) > 0 {
		infoSend, infoRecv = infoRecv, infoSend
	}

	hkdfSend := hkdf.New(sha256.New, sharedSecret, salt, infoSend)
	hkdfRecv := hkdf.New(sha256.New, sharedSecret, salt, infoRecv)

	sendKey = make([]byte, 32)
	recvKey = make([]byte, 32)

	if _, err := io.ReadFull(hkdfSend, sendKey); err != nil {
		return nil, nil, err
	}
	if _, err := io.ReadFull(hkdfRecv, recvKey); err != nil {
		return nil, nil, err
	}

	return sendKey, recvKey, nil
}
