/*
Package socks5 provides SOCKS5 client and server implementations.

 https://tools.ietf.org/html/rfc1928
 https://tools.ietf.org/html/rfc1929


*/
package socks5

import (
	"errors"
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
