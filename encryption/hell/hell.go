package hell

import (
	"encoding/binary"
	"io"

	libraryEncryption "github.com/pperminov/library/encryption"
	libraryNetwork "github.com/pperminov/library/network"
)

func MakeAHellCircle(connection libraryNetwork.GenericConnection) (libraryNetwork.GenericConnection, error) {
	toEncrypt, toDecrypt, err := libraryEncryption.GetECDHKeysFromConnectionWithKeyDerivation(connection)
	if err != nil {
		return nil, err
	}
	salt, err := libraryEncryption.GetECDHKeysFromConnection(connection)
	if err != nil {
		return nil, err
	}
	EDToEncrypt, err := libraryEncryption.NewED(toEncrypt, salt, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	EDToDecrypt, err := libraryEncryption.NewED(toDecrypt, salt, 0, 0, 0)
	if err != nil {
		return nil, err
	}
	return &HellCircle{
		EDToEncrypt: EDToEncrypt,
		EDToDecrypt: EDToDecrypt,
		connection:  connection,
	}, nil
}

type HellCircle struct {
	connection               libraryNetwork.GenericConnection
	EDToDecrypt, EDToEncrypt *libraryEncryption.ED
}

func (m HellCircle) Read(b []byte) (int, error) {
	var len1 uint32
	err := binary.Read(m.connection, binary.BigEndian, &len1)
	if err != nil {
		return 0, err
	}
	var data = make([]byte, len1)
	_, err = io.ReadFull(m.connection, data)
	if err != nil {
		return 0, err
	}
	decryptedData, err := m.EDToDecrypt.DecryptAES(data)
	if err != nil {
		return 0, err
	}
	if len(b) < len(decryptedData) {
		return 0, io.ErrShortBuffer
	}
	n := copy(b, decryptedData)
	return n, nil
}

func (m HellCircle) Write(b []byte) (int, error) {
	encryptedData, err := m.EDToEncrypt.EncryptAES(b)
	if err != nil {
		return 0, err
	}
	len1 := uint32(len(encryptedData))
	err = binary.Write(m.connection, binary.BigEndian, len1)
	if err != nil {
		return 0, err
	}
	_, err = m.connection.Write(encryptedData)
	if err != nil {
		return 0, err
	}
	return len(b), err
}

func (m HellCircle) Close() error {
	return m.connection.Close()
}
