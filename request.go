package socks5

import (
	"errors"
)

// Request has the detail of the request message
type Request struct {
	Cmd  Command
	Addr *Address
}

// ErrInvalidRequest represents invalid request
var ErrInvalidRequest = errors.New("invalid request")

// NewRequest return the request
func NewRequest(network, address string) (*Request, error) {
	cmd, err := getCommand(network)
	if err != nil {
		return nil, err
	}
	addr, err := NewAddress(address)
	if err != nil {
		return nil, err
	}
	return &Request{
		Cmd:  cmd,
		Addr: addr,
	}, nil
}
