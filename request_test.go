package socks5

import (
	"bytes"
	"fmt"
	"testing"
)

func TestRequest(t *testing.T) {
	t1 := make(map[string]string)
	t1["tcp"] = "127.0.0.1:0"
	t1["tcp4"] = "127.0.0.1:0"
	t1["tcp6"] = "127.0.0.1:0"
	t1["udp"] = "127.0.0.1:0"
	t1["udp4"] = "127.0.0.1:0"
	t1["udp6"] = "127.0.0.1:0"

	for n, a := range t1 {
		if err := testRequest(n, a); err != nil {
			fmt.Printf("%s : %s\n", n, a)
			t.Fatal(err)
		}
	}

	t2 := make(map[string]string)
	t2["ip"] = "127.0.0.1:0"
	for n, a := range t2 {
		if err := testRequest(n, a); err == nil {
			fmt.Printf("%s : %s\n", n, a)
			t.Fatal("Error")
		}
	}
}

func testRequest(network, addr string) error {
	var buf bytes.Buffer
	a, err := newRequest(network, addr)
	if err != nil {
		return err
	}
	if err := a.send(&buf); err != nil {
		return err
	}
	b, err := readRequest(&buf)
	if err != nil {
		return err
	}
	if a.Cmd != b.Cmd || a.Dst.String() != b.Dst.String() {
		return fmt.Errorf("Error")
	}
	return nil
}
