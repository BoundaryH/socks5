package socks5

import "errors"

// Method represents identify method of SOCKS5
type Method uint8

// Various constants
const (
	MethodNotRequired      Method = 0x00
	MethodUsernamePassword Method = 0x02
	MethodNoAcceptable     Method = 0xff
)

// ErrMethodNoAcceptable respresents invalid method
var ErrMethodNoAcceptable = errors.New("method no acceptable")
