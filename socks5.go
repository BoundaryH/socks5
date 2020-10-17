/*
Package socks5 provides SOCKS5 client and server implementations.

 https://tools.ietf.org/html/rfc1928
 https://tools.ietf.org/html/rfc1929


*/
package socks5

import (
	"errors"
	"net"
)

// Various constants
const (
	Version5 = 0x05
	Reserved = 0x00
)

// Various errors
var (
	ErrInvalidVersion = errors.New("invalid socks version")
)

// ListenAndServe listens on the network address and then calls Serve
func ListenAndServe(address string) error {
	return NewServer().ListenAndServe(address)
}

// ListenAndServeWithAuth listens on the network address and then calls Serve
func ListenAndServeWithAuth(address, username, password string) error {
	return NewServerWithAuth(username, password).ListenAndServe(address)
}

// Serve accepts incoming connections on the listener
// and creating a new service goroutine for each.
func Serve(l net.Listener) error {
	return NewServer().Serve(l)
}
