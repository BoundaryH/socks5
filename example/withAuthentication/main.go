package main

import (
	"fmt"
	"log"
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
	conn, err := client.Dial("tcp", "google.com:443")
	if err != nil {
		log.Fatal(err)
	}
	defer conn.Close()

	fmt.Println("Success")
}

func server() {
	pw := make(map[string]string)
	pw["username"] = "password"
	log.Fatal(socks5.ListenAndServeWithAuth("tcp", "127.0.0.1:8888", pw))
}
