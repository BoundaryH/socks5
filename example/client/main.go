package main

import (
	"fmt"
	"io"
	"log"
	"net"
	"socks5"
	"time"
)

// example
func main() {
	go server()
	time.Sleep(time.Second)

	client, err := socks5.NewClientWithAuth("127.0.0.1:8888", "username", "password")
	if err != nil {
		log.Fatal(err)
	}
	conn, err := client.Dial("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()
	fmt.Println("Client", conn.RemoteAddr())
	if _, err := conn.Write([]byte("Hello abde")); err != nil {
		log.Fatal(err)
	}
	buf := make([]byte, 20)
	n, err := conn.Read(buf)
	if err != nil {
		log.Fatal(">>> ", err)
	}
	fmt.Println(string(buf[:n]))

	fmt.Println("Success")
}

func server() {
	//log.Fatal(socks5.ListenAndServeWithAuth("127.0.0.1:8888", "username", "password"))
	ln, err := net.Listen("tcp", "127.0.0.1:8080")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := ln.Accept()
		if err != nil {
			log.Fatal(err)
		}
		go handle(conn)
	}
}

func handle(conn net.Conn) {
	fmt.Println("Server", conn.RemoteAddr())
	if _, err := io.Copy(conn, conn); err != nil {
		log.Fatal(err)
	}
}
