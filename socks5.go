/*
Package socks5 provides SOCKS5 client and server implementations.

 https://tools.ietf.org/html/rfc1928
 https://tools.ietf.org/html/rfc1929


*/
package socks5

import (
	"errors"
	"fmt"
	"io"
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

func readSingleByte(r io.Reader) (byte, error) {
	b := []byte{0}
	_, err := io.ReadFull(r, b)
	return b[0], err
}

func sendMethods(conn io.Writer, methods []Method) (err error) {
	if len(methods) == 0 || len(methods) > 255 {
		return fmt.Errorf("invalid methods")
	}
	buf := make([]byte, 2, 2+len(methods))
	buf[0] = Version5
	buf[1] = byte(len(methods))
	for _, m := range methods {
		buf = append(buf, byte(m))
	}
	_, err = conn.Write(buf)
	return
}

func readMethods(conn io.Reader) ([]Method, error) {
	version, err := readSingleByte(conn)
	if err != nil {
		return nil, err
	}

	if version != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, version)
	}

	numMethods, err := readSingleByte(conn)
	if err != nil {
		return nil, err
	}

	buf := make([]byte, numMethods)
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	methods := make([]Method, len(buf))
	for i, m := range buf {
		methods[i] = Method(m)
	}
	return methods, nil
}

func sendMethodSelection(conn io.Writer, method Method) (err error) {
	_, err = conn.Write([]byte{Version5, byte(method)})
	return
}

func readMethodSelection(conn io.Reader) (Method, error) {
	buf := []byte{0, 0}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return MethodNoAcceptable, err
	}
	if buf[0] != Version5 {
		return MethodNoAcceptable, fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}
	return Method(buf[1]), nil
}

func sendAuthentication(conn io.Writer, auth *Authentication) (err error) {
	_, err = conn.Write([]byte{Version5})
	if err != nil {
		return
	}
	if auth == nil {
		return ErrInvalidAuth
	}
	var b []byte
	b, err = auth.ToByte()
	if err != nil {
		return
	}
	_, err = conn.Write(b)
	return
}

func readAuthentication(conn io.Reader) (*Authentication, error) {
	ver, err := readSingleByte(conn)
	if err != nil {
		return nil, err
	}
	if ver != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, ver)
	}
	return ReadAuth(conn)
}

func sendAuthStatus(conn io.Writer, success bool) (err error) {
	if success {
		_, err = conn.Write([]byte{Version5, byte(AuthSuccess)})
	} else {
		_, err = conn.Write([]byte{Version5, byte(AuthFailure)})
	}
	return
}

func readAuthStatus(conn io.Reader) (err error) {
	buf := []byte{0, 0}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return err
	}
	if buf[0] != Version5 {
		return fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}
	if AuthStatus(buf[1]) != AuthSuccess {
		return ErrAuthFailed
	}
	return nil
}

func sendRequest(conn io.Writer, req *Request) (err error) {
	if req == nil || req.Addr == nil {
		return ErrInvalidRequest
	}
	var addr []byte
	addr, err = req.Addr.ToByte()
	if err != nil {
		return
	}
	_, err = conn.Write([]byte{Version5, byte(req.Cmd), Reserved})
	if err != nil {
		return
	}
	_, err = conn.Write(addr)
	return
}

func readRequest(conn io.Reader) (*Request, error) {
	buf := []byte{0, 0, 0}
	if _, err := io.ReadFull(conn, buf); err != nil {
		return nil, err
	}
	if buf[0] != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}

	addr, err := ReadAddress(conn)
	if err != nil {
		return nil, err
	}
	return &Request{
		Cmd:  Command(buf[1]),
		Addr: addr,
	}, nil
}

func sendReply(conn io.Writer, rep Reply, bind *Address) (err error) {
	_, err = conn.Write([]byte{Version5, byte(rep), Reserved})
	if err != nil {
		return
	}
	if rep != ReplySucceed {
		return nil
	}
	if bind == nil {
		return fmt.Errorf("nil bound address")
	}
	var addr []byte
	addr, err = bind.ToByte()
	if err != nil {
		return
	}
	_, err = conn.Write(addr)
	return
}

func readReply(conn io.Reader) (bind *Address, err error) {
	buf := []byte{0, 0, 0}
	_, err = io.ReadFull(conn, buf)
	if err != nil {
		return
	}
	if buf[0] != Version5 {
		err = fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
		return
	}
	if reply := Reply(buf[1]); reply != ReplySucceed {
		err = fmt.Errorf("%w : %s", ErrReplyFailure, reply.String())
		return
	}
	bind, err = ReadAddress(conn)
	return
}
