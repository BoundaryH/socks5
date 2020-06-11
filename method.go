package socks5

import (
	"errors"
	"fmt"
	"io"
)

// Method represents identify method of SOCKS5
type Method byte

// Various constants
const (
	MethodNotRequired      Method = 0x00
	MethodUsernamePassword Method = 0x02
	MethodNoAcceptable     Method = 0xff
)

// ErrMethodNoAcceptable respresents invalid method
var ErrMethodNoAcceptable = errors.New("method no acceptable")

func sendMethods(w io.Writer, methods []Method) (err error) {
	if len(methods) == 0 || len(methods) > 255 {
		return fmt.Errorf("invalid methods")
	}
	buf := make([]byte, 2, 2+len(methods))
	buf[0] = Version5
	buf[1] = byte(len(methods))
	for _, m := range methods {
		buf = append(buf, byte(m))
	}
	_, err = w.Write(buf)
	return
}

func readMethods(r io.Reader) ([]Method, error) {
	version, err := readSingleByte(r)
	if err != nil {
		return nil, err
	}

	if version != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, version)
	}

	numMethods, err := readSingleByte(r)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, numMethods)
	if _, err := io.ReadFull(r, buf); err != nil {
		return nil, err
	}
	methods := make([]Method, len(buf))
	for i, m := range buf {
		methods[i] = Method(m)
	}
	return methods, nil
}

func sendMethodSelection(w io.Writer, method Method) (err error) {
	_, err = w.Write([]byte{Version5, byte(method)})
	return
}

func readMethodSelection(r io.Reader) (Method, error) {
	buf := []byte{0, 0}
	if _, err := io.ReadFull(r, buf); err != nil {
		return MethodNoAcceptable, err
	}
	if buf[0] != Version5 {
		return MethodNoAcceptable, fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}
	return Method(buf[1]), nil
}
