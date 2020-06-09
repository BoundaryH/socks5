package socks5

import (
	"bytes"
	"errors"
	"io"
)

// AuthStatus represents authentication status
type AuthStatus uint8

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
	Username []byte
	Password []byte
}

// NewAuthentication return the Authentication
func NewAuthentication(username, password string) (*Authentication, error) {
	a := &Authentication{
		Username: []byte(username),
		Password: []byte(password),
	}
	if len(a.Username) > 255 || len(a.Password) > 255 {
		return nil, ErrInvalidAuth
	}
	return a, nil
}

// ReadAuth return the Authentication which read from reader
func ReadAuth(r io.Reader) (*Authentication, error) {
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
		Username: username,
		Password: password,
	}, nil
}

// ToByte return a slice of byte
// which is the format of SOCKS5 protocol
func (a *Authentication) ToByte() ([]byte, error) {
	if len(a.Username) > 255 || len(a.Password) > 255 {
		return nil, ErrInvalidAuth
	}
	var buf bytes.Buffer
	buf.Grow(2 + len(a.Username) + len(a.Password))
	buf.WriteByte(byte(len(a.Username)))
	buf.Write(a.Username)
	buf.WriteByte(byte(len(a.Password)))
	buf.Write(a.Password)
	return buf.Bytes(), nil
}

// Verify the password
func (a *Authentication) Verify(user, pw string) bool {
	return bytes.Equal(a.Username, []byte(user)) &&
		bytes.Equal(a.Password, []byte(pw))
}
