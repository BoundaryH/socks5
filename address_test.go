package socks5

import (
	"bytes"
	"strings"
	"testing"
)

func TestAddr(t *testing.T) {
	testAddr("hello.com:16", t)
	testAddr("192.0.2.1:245", t)
	testAddr("[2001:db8::68]:0", t)
	if _, err := NewAddress(strings.Repeat("xx", 200) + ":88"); err == nil {
		t.Fatal("Err")
	}
}

func testAddr(address string, t *testing.T) {
	a, err := NewAddress(address)
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.ToByte()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadAddress(bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	if !a.Equal(c) {
		t.Fatal("Err")
	}
}
