package socks5

import (
	"errors"
	"fmt"
	"io"
)

// AuthStatus represents authentication status
type AuthStatus byte

// Various constants
const (
	AuthSuccess AuthStatus = 0x00
	AuthFailure AuthStatus = 0xff
)

var (
	// ErrInvalidAuth represents auth is nil or username/password is too long
	ErrInvalidAuth = errors.New("invalid authentication")

	// ErrAuthFailed represents username/password are not correct
	ErrAuthFailed = errors.New("username/password authentication failed")
)

// Authentication is the credentials
// for the username/password authentication method.
type Authentication struct {
	Ver      byte
	Username []byte
	Password []byte
}

func newAuth(username, password string) (*Authentication, error) {
	a := &Authentication{
		Ver:      Version5,
		Username: []byte(username),
		Password: []byte(password),
	}
	if len(a.Username) > 255 || len(a.Password) > 255 {
		return nil, ErrInvalidAuth
	}
	return a, nil
}

func readAuth(r io.Reader) (*Authentication, error) {
	ver, err := readSingleByte(r)
	if err != nil {
		return nil, err
	}
	if ver != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, ver)
	}

	uLen, err := readSingleByte(r)
	if err != nil {
		return nil, err
	}
	username := make([]byte, uLen)
	if _, err := io.ReadFull(r, username); err != nil {
		return nil, err
	}

	pLen, err := readSingleByte(r)
	if err != nil {
		return nil, err
	}
	password := make([]byte, pLen)
	if _, err := io.ReadFull(r, password); err != nil {
		return nil, err
	}
	return &Authentication{
		Ver:      ver,
		Username: username,
		Password: password,
	}, nil
}

func (a *Authentication) send(w io.Writer) (err error) {
	if len(a.Username) > 255 || len(a.Password) > 255 {
		return ErrInvalidAuth
	}
	buf := make([]byte, 2, 3+len(a.Username)+len(a.Password))
	buf[0] = a.Ver
	buf[1] = byte(len(a.Username))
	buf = append(buf, a.Username...)
	buf = append(buf, byte(len(a.Password)))
	buf = append(buf, a.Password...)
	_, err = w.Write(buf)
	return
}

func sendAuthStatus(w io.Writer, success bool) (err error) {
	if success {
		_, err = w.Write([]byte{Version5, byte(AuthSuccess)})
	} else {
		_, err = w.Write([]byte{Version5, byte(AuthFailure)})
	}
	return
}

func readAuthStatus(r io.Reader) (err error) {
	buf := []byte{0, 0}
	if _, err := io.ReadFull(r, buf); err != nil {
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
