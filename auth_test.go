package socks5

import (
	"bytes"
	"fmt"
	"strings"
	"testing"
)

func TestAuth(t *testing.T) {
	t1 := make(map[string]string)
	t1["abc"] = "12345678"
	t1[""] = ""
	t1[""] = "password"
	t1["name"] = "password"
	for u, p := range t1 {
		if err := testAuth(u, p); err != nil {
			fmt.Printf("%s : %s\n", u, p)
			t.Fatal(err)
		}
	}

	t2 := make(map[string]string)
	x := strings.Repeat("xx", 200)
	t2[x] = ""
	t2["user"] = x
	for u, p := range t2 {
		if err := testAuth(u, p); err == nil {
			fmt.Printf("%s : %s\n", u, p)
			t.Fatal("Error")
		}
	}
}

func testAuth(name, pw string) error {
	var buf bytes.Buffer
	a, err := newAuth(name, pw)
	if err != nil {
		return err
	}
	if err := a.send(&buf); err != nil {
		return err
	}
	b, err := readAuth(&buf)
	if err != nil {
		return err
	}
	if !bytes.Equal(a.Username, b.Username) ||
		!bytes.Equal(a.Password, b.Password) {
		return err
	}
	return nil
}
