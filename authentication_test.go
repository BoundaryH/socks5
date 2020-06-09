package socks5

import (
	"bytes"
	"strings"
	"testing"
)

func TestAuth(t *testing.T) {
	testAuth("abc", "12345678", t)
	testAuth("", "", t)
	testAuth("", "password", t)
	testAuth("name", "", t)

	x := strings.Repeat("xx", 200)
	if _, err := NewAuthentication(x, x); err == nil {
		t.Fatal("Err")
	}
}

func testAuth(name, pw string, t *testing.T) {
	a, err := NewAuthentication(name, pw)
	if err != nil {
		t.Fatal(err)
	}
	b, err := a.ToByte()
	if err != nil {
		t.Fatal(err)
	}
	c, err := ReadAuth(bytes.NewBuffer(b))
	if err != nil {
		t.Fatal(err)
	}
	if !c.Verify(name, pw) {
		t.Fatal("Err")
	}
}
