package socks5

import (
	"net"
	"testing"
)

func TestNoAuth(t *testing.T) {
	// Target
	l1, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	target := l1.Addr().String()

	// Server
	s := NewServer()
	l2, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		t.Fatal(s.Serve(l2))
	}()
	proxy := l2.Addr().String()

	// Client
	c, err := NewClient(proxy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dial("tcp", target); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dial("udp", target); err == nil {
		t.Fatal("Error")
	}

	// with user/password
	c, err = NewClientWithAuth(proxy, "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dial("tcp", target); err != nil {
		t.Fatal(err)
	}
}

func TestWithAuth(t *testing.T) {
	// Target
	l1, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	target := l1.Addr().String()

	// Server
	s := NewServerWithAuth("user", "password")
	l2, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		t.Fatal(s.Serve(l2))
	}()
	proxy := l2.Addr().String()

	// Client
	c, err := NewClientWithAuth(proxy, "user", "password")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := c.Dial("tcp", target); err != nil {
		t.Fatal(err)
	}
}
