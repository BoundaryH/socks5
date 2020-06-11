package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Request has the detail of the request message
type Request struct {
	Ver byte
	Cmd Command
	Dst Address
}

// ErrInvalidRequest represents invalid request
var ErrInvalidRequest = errors.New("invalid request")

// NewRequest return the request
func newRequest(network, address string) (*Request, error) {
	cmd, err := getCommand(network)
	if err != nil {
		return nil, err
	}
	addr, err := NewAddress(address)
	if err != nil {
		return nil, err
	}
	return &Request{
		Cmd: cmd,
		Dst: *addr,
	}, nil
}

func readRequest(r io.Reader) (*Request, error) {
	buf := []byte{0, 0, 0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	if buf[0] != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}

	addr, err := readAddress(r)
	if err != nil {
		return nil, err
	}
	return &Request{
		Ver: buf[0],
		Cmd: Command(buf[1]),
		Dst: *addr,
	}, nil
}

func (req *Request) send(w io.Writer) (err error) {
	if req == nil {
		return ErrInvalidRequest
	}
	_, err = w.Write([]byte{Version5, byte(req.Cmd), Reserved})
	if err != nil {
		return
	}
	return req.Dst.send(w)
}
