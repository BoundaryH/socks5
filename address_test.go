package socks5

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestAddr(t *testing.T) {
	t1 := []string{
		"hello.com:16",
		"192.0.2.1:245",
		"[2001:db8::68]:0",
	}
	for _, i := range t1 {
		if err := testAddr(i); err != nil {
			fmt.Println(i)
			t.Fatal(err)
		}
	}
	t2 := []string{
		"",
		":",
		":200",
		"abc:",
		"demo:87654",
		strings.Repeat("xx", 200) + ":88",
	}
	for _, i := range t2 {
		if _, err := NewAddress(i); err == nil {
			fmt.Println(i)
			t.Fatal("Error")
		}
	}
}

func testAddr(address string) error {
	var buf bytes.Buffer
	a, err := NewAddress(address)
	if err != nil {
		return err
	}
	if err := a.send(&buf); err != nil {
		return err
	}
	b, err := readAddress(&buf)
	if err != nil {
		return err
	}
	if !equal(a, b) {
		return fmt.Errorf("%s != %s", a.String(), b.String())
	}
	return nil
}

func equal(a *Address, b *Address) bool {
	if a.Type != b.Type || a.Port != b.Port {
		return false
	}
	if a.Type == AddrTypeDN {
		return a.Domain == b.Domain
	}
	return a.IP.Equal(b.IP)
}
