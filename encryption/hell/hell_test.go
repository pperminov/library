package hell_test

import (
	"testing"

	"github.com/pperminov/library/encryption/hell"
	libraryNetwork "github.com/pperminov/library/network"
	libraryNumbers "github.com/pperminov/library/numbers"
	libraryStrings "github.com/pperminov/library/strings"
	libraryTesting "github.com/pperminov/library/testing"
	"github.com/stretchr/testify/require"
)

func TestHell(t *testing.T) {
	conn1, conn2 := libraryTesting.NewLinkedMockConnections()

	done := make(chan bool, 2)

	WriteThrough1 := make(chan []byte)
	WriteThrough2 := make(chan []byte)

	ReadFrom1 := make(chan []byte)
	ReadFrom2 := make(chan []byte)

	writeToFirst := func(s []byte) {
		WriteThrough1 <- s
	}
	writeToSecond := func(s []byte) {
		WriteThrough2 <- s
	}
	readFromFirst := func() []byte {
		return <-ReadFrom1
	}
	readFromSecond := func() []byte {
		return <-ReadFrom2
	}

	go func() {
		h, err := hell.MakeAHellCircle(conn1)
		require.NoError(t, err)
		done <- true
		go writer(WriteThrough1, h, t)
		go reader(ReadFrom1, h, t)
	}()
	go func() {
		h, err := hell.MakeAHellCircle(conn2)
		require.NoError(t, err)
		done <- true
		go writer(WriteThrough2, h, t)
		go reader(ReadFrom2, h, t)

	}()

	<-done
	<-done

	sample1 := []byte(libraryStrings.RandString(666))
	writeToFirst(sample1)
	sample2 := readFromSecond()
	require.Equal(t, sample1, sample2)

	sample3 := []byte(libraryStrings.RandString(666))
	writeToSecond(sample3)
	sample4 := readFromFirst()
	require.Equal(t, sample3, sample4)

	funcsToGo := make(chan func(), 500)
	go func() {
		for f := range funcsToGo {
			f()
		}
		done <- true
	}()

	makeFuncToGo := func(sample []byte, from func() []byte) func() {
		return func() {
			require.Equal(t, from(), sample)
		}
	}
	for i := 1; i <= 500; i++ {
		sample1 := []byte(libraryStrings.RandString(i))
		if n, _ := libraryNumbers.SimpleRand(); n%2 == 0 {
			writeToFirst(sample1)
			funcsToGo <- makeFuncToGo(sample1, readFromSecond)
		} else {
			writeToSecond(sample1)
			funcsToGo <- makeFuncToGo(sample1, readFromFirst)

		}
	}
	close(funcsToGo)
	<-done
}

func BenchmarkHellG(b *testing.B) {
	conn1, conn2 := libraryTesting.NewLinkedMockConnections()
	done := make(chan bool, 2)
	WriteThrough1 := make(chan []byte, 2)
	WriteThrough2 := make(chan []byte, 2)
	ReadFrom1 := make(chan []byte, 2)
	ReadFrom2 := make(chan []byte, 2)
	go func() {
		h, err := hell.MakeAHellCircle(conn1)
		require.NoError(b, err)
		done <- true
		go writerB(WriteThrough1, h)
		go readerB(ReadFrom1, h)
	}()
	go func() {
		h, err := hell.MakeAHellCircle(conn2)
		require.NoError(b, err)
		done <- true
		go writerB(WriteThrough2, h)
		go readerB(ReadFrom2, h)

	}()
	<-done
	<-done
	sample1 := []byte(libraryStrings.RandString(666))
	for b.Loop() {
		WriteThrough1 <- sample1
		<-ReadFrom2
	}

}

func writer(WriteThrough chan []byte, h libraryNetwork.GenericConnection, t testing.TB) {
	for {
		x := <-WriteThrough
		_, err := h.Write(x)
		require.NoError(t, err)
	}
}

func reader(ReadFrom chan []byte, h libraryNetwork.GenericConnection, t testing.TB) {
	for {
		b := make([]byte, 1024)
		n, err := h.Read(b)
		require.NoError(t, err)
		ReadFrom <- b[:n]
	}
}

func writerB(WriteThrough chan []byte, h libraryNetwork.GenericConnection) {
	for {
		x := <-WriteThrough
		h.Write(x)
	}
}

func readerB(ReadFrom chan []byte, h libraryNetwork.GenericConnection) {
	for {
		b := make([]byte, 1024)
		n, _ := h.Read(b)
		ReadFrom <- b[:n]
	}
}
