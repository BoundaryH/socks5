package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
)

// Server defines parameters for running an SOCKS5 server
type Server struct {
	Log func(Method, *Authentication, *Request, error)

	SelectMethod func(ctx context.Context, methods []Method) Method

	// return true indicates success
	// return false, handshake will be abort
	Authenticate func(ctx context.Context, auth *Authentication) bool

	// if err != nil, target should be nil
	HandleRequest func(ctx context.Context, auth *Authentication, req *Request) (*Reply, io.ReadWriteCloser, error)
}

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
	var s Server
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(context.Background(), conn)
	}
}

// NewServer creates a new SOCKS5 proxy Server
func NewServer() *Server {
	return &Server{}
}

// NewServerWithAuth creates a new SOCKS5 proxy Server
func NewServerWithAuth(username, password string) *Server {
	return &Server{
		SelectMethod: SelectMethodUserPass,
		Authenticate: func(ctx context.Context, auth *Authentication) bool {
			return auth != nil && string(auth.Username) == username &&
				string(auth.Password) == password
		},
	}
}

// ListenAndServe listens on the network address and then calls Serve
func (s *Server) ListenAndServe(address string) error {
	l, err := net.Listen("tcp", address)
	if err != nil {
		return err
	}
	return s.Serve(l)
}

// Serve accepts incoming connections on the listener
// and creating a new service goroutine for each.
func (s *Server) Serve(l net.Listener) error {
	for {
		conn, err := l.Accept()
		if err != nil {
			return err
		}
		go s.ServeConn(context.Background(), conn)
	}
}

// ServeConn accepts a connection and handle SOCKS5 request
func (s *Server) ServeConn(ctx context.Context, conn io.ReadWriteCloser) {
	defer conn.Close()
	m, auth, req, err := s.handle(ctx, conn)
	if err != nil {
		if s.Log != nil {
			s.Log(m, auth, req, err)
		} else {
			//log.Println(err)
		}
	}
}

func (s *Server) handle(ctx context.Context, conn io.ReadWriteCloser) (
	m Method, auth *Authentication, req *Request, err error) {
	// Select method
	var methods []Method
	methods, err = readMethods(conn)
	if err != nil {
		return
	}
	if s.SelectMethod != nil {
		m = s.SelectMethod(ctx, methods)
	} else {
		m = SelectMethodNoRequired(ctx, methods)
	}
	err = sendMethodSelection(conn, m)
	if err != nil {
		return
	}

	// Authenticate
	switch m {
	case MethodNotRequired:
	case MethodUsernamePassword:
		auth, err = readAuth(conn)
		if err != nil {
			return
		}
		result := false
		if s.Authenticate != nil {
			result = s.Authenticate(ctx, auth)
		}
		err = sendAuthStatus(conn, result)
		if err != nil {
			return
		}
		if !result {
			err = ErrAuthFailed
			return
		}
	default:
		err = fmt.Errorf("%w : %02x", ErrMethodNoAcceptable, m)
		return
	}

	// Handle request
	var reply *Reply
	var target io.ReadWriteCloser
	req, err = readRequest(conn)
	if err != nil {
		return
	}
	if s.HandleRequest != nil {
		reply, target, err = s.HandleRequest(ctx, auth, req)
	} else {
		reply, target, err = HandleRequest(ctx, auth, req)
	}
	if err != nil {
		if reply == nil {
			reply, _ = newReply(ReplyFailure, "0.0.0.0:0")
		}
		if e := reply.send(conn); e != nil {
			err = e
			return
		}
		return
	}
	if target == nil {
		err = fmt.Errorf("connection target is nil")
		return
	}
	defer target.Close()

	if reply == nil {
		err = fmt.Errorf("reply is nil")
		return
	}
	err = reply.send(conn)
	if err != nil {
		return
	}
	if reply.Code != ReplySucceed {
		err = fmt.Errorf("Reply : %s", reply.Code.String())
		return
	}

	// Start Proxy
	err = pipe(ctx, conn, target)
	return
}

// SelectMethodNoRequired is the default value of Server.SelectMethod
func SelectMethodNoRequired(ctx context.Context, methods []Method) Method {
	for _, m := range methods {
		if m == MethodNotRequired {
			return m
		}
	}
	return MethodNoAcceptable
}

// SelectMethodUserPass only support username/password method
func SelectMethodUserPass(ctx context.Context, methods []Method) Method {
	for _, m := range methods {
		if m == MethodUsernamePassword {
			return m
		}
	}
	return MethodNoAcceptable
}

// HandleRequest is the default value of Server.HandleRequest
func HandleRequest(ctx context.Context, auth *Authentication, req *Request) (
	*Reply, io.ReadWriteCloser, error) {
	switch req.Cmd {
	case CmdConnect:
		return handleConnect(req.Dst.String())
	case CmdBind:
	case CmdUDP:
	default:
	}
	return nil, nil, ErrCmdUnsupported
}

func handleConnect(addr string) (
	reply *Reply, target io.ReadWriteCloser, err error) {
	var conn net.Conn
	conn, err = net.Dial("tcp", addr)
	if err != nil {
		reply, _ = newReply(getReplyCode(err.Error()), "0.0.0.0:0")
		return
	}
	reply, err = newReply(ReplySucceed, conn.LocalAddr().String())
	if err != nil {
		conn.Close()
		return
	}
	target = conn
	return
}
