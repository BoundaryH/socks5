package socks5

import (
	"fmt"
	"io"
	"net"
)

// Client holds configure and options
type Client struct {
	methods []Method
	auth    *Authentication
	proxy   string
}

// NewClient returns a new Client with "no authentication required"
func NewClient(proxy string) (*Client, error) {
	return &Client{
		methods: []Method{MethodNotRequired},
		auth:    nil,
		proxy:   proxy,
	}, nil
}

// NewClientWithAuth returns a new Client with "username/password"
// "no authentication require" is also enabled
func NewClientWithAuth(proxy, username, password string) (*Client, error) {
	auth, err := NewAuthentication(username, password)
	if err != nil {
		return nil, err
	}
	return &Client{
		methods: []Method{MethodUsernamePassword, MethodNotRequired},
		auth:    auth,
		proxy:   proxy,
	}, nil
}

// Dial connects to the provided address via SOCKS5 proxy
func (c *Client) Dial(network, address string) (conn net.Conn, err error) {
	var req *Request
	req, err = NewRequest(network, address)
	if err != nil {
		return
	}
	conn, err = net.Dial("tcp", c.proxy)
	if err != nil {
		return
	}
	defer func() {
		if err != nil {
			conn.Close()
		}
	}()

	_, err = Dial(conn, c.methods, c.auth, req)
	return
}

// Dial connects to the provided address via SOCKS5 proxy
func Dial(conn io.ReadWriter, methods []Method,
	auth *Authentication, req *Request) (bind *Address, err error) {

	var method Method
	err = sendMethods(conn, methods)
	if err != nil {
		return
	}
	method, err = readMethodSelection(conn)
	if err != nil {
		return
	}

	switch method {
	case MethodNotRequired:
	case MethodUsernamePassword:
		if auth == nil {
			err = ErrInvalidAuth
			return
		}
		err = sendAuthentication(conn, auth)
		if err != nil {
			return
		}
		err = readAuthStatus(conn)
		if err != nil {
			return
		}
	default:
		err = fmt.Errorf("%w : %02x", ErrMethodNoAcceptable, method)
		return
	}

	err = sendRequest(conn, req)
	if err != nil {
		return
	}
	bind, err = readReply(conn)
	if err != nil {
		return
	}
	return
}
