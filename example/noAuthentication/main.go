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

	client, err := socks5.NewClient("127.0.0.1:8888")
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
	log.Fatal(socks5.ListenAndServe("127.0.0.1:8888"))
}
