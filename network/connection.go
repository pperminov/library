package libraryNetwork

import (
	"io"

	libraryErrors "github.com/pperminov/library/errors"
)

func ReadConnection[T uint | uint32 | uint64](conn GenericConnection, length T) (data []byte, err error) {
	if length == 0 {
		length = 4096
	}
	for _, params := range HowMany(length) {
		chunkSize := params[0]
		count := params[1]
		for i := 0; i < count; i++ {
			buffer := make([]byte, chunkSize)
			totalRead := 0
			for totalRead < chunkSize {
				n, err := conn.Read(buffer[totalRead:])
				if n > 0 {
					totalRead += n
					data = append(data, buffer[totalRead-n:totalRead]...)
				}
				if err != nil {
					return data, err
				}
			}
		}
	}
	return
}

func WriteConnection(conn GenericConnection, data []byte) error {
	total := 0
	for total < len(data) {
		n, err := conn.Write(data[total:])
		if err != nil {
			return err
		}
		total += n
	}
	return nil
}

func ConnectPipes(conn1, conn2 GenericConnection, errChan chan error) {
	copyData := func(dst, src GenericConnection, errChan chan error) {
		_, err := io.Copy(dst, src)
		if errChan != nil {
			errChan <- err
		} else {
			libraryErrors.Errorer(err)
		}
	}
	go copyData(conn1, conn2, errChan)
	go copyData(conn2, conn1, errChan)
}
