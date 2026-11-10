package main

import (
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"net"
	"os"

	"github.com/pperminov/library/encryption/hell"
)

const defport = "51498"

func listen(port string) {
	listener, err := net.Listen("tcp", "0.0.0.0:"+port)
	if err != nil {
		panic(err)
	}
	defer listener.Close()
	fmt.Println("listening")

	acc, err := listener.Accept()
	if err != nil {
		panic(err)
	}
	circle, err := hell.MakeAHellCircle(acc)
	if err != nil {
		panic(err)
	}
	defer circle.Close()
	var len1 int64
	err = binary.Read(circle, binary.BigEndian, &len1)
	if err != nil {
		panic(err)
	}
	nameBytes := make([]byte, 8024)
	y, err := circle.Read(nameBytes)
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile(string(nameBytes[:y]), os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0644)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	oi, err := io.CopyN(f, circle, len1)
	if err != nil {
		panic(err)
	}
	if oi != len1 {
		panic(fmt.Sprintf("Expected: %d but Received: %d", len1, oi))
	}
	return

}

func main() {
	port := flag.String("port", defport, "server port")
	flag.Parse()
	args := flag.Args()
	if len(args) == 0 {
		listen(*port)
		return
	} else if len(args) != 2 {
		panic("less than 2 arguments")
	}
	connection, err := net.Dial("tcp", args[1]+":"+*port)
	if err != nil {
		panic(err)
	}
	circle, err := hell.MakeAHellCircle(connection)
	if err != nil {
		panic(err)
	}
	defer circle.Close()
	stat, err := os.Stat(args[0])
	if err != nil {
		panic(err)
	}
	name := stat.Name()
	size := stat.Size()
	err = binary.Write(circle, binary.BigEndian, size)
	if err != nil {
		panic(err)
	}
	_, err = circle.Write([]byte(name))
	if err != nil {
		panic(err)
	}
	f, err := os.OpenFile(args[0], os.O_RDONLY, 0)
	if err != nil {
		panic(err)
	}
	defer f.Close()
	_, err = io.Copy(circle, f)
	if err != nil {
		panic(err)
	}
}
