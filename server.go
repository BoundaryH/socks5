package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
)

// Server defines parameters for running an SOCKS5 server
type Server struct {
	Logger        func(error)
	SelectMethod  func(ctx context.Context, methods []Method) Method
	Authenticate  func(ctx context.Context, auth *Authentication) bool
	HandleRequest func(ctx context.Context, req *Request) (Reply, *Address, io.ReadWriteCloser)
	HandleProxy   func(ctx context.Context, conn io.ReadWriter, target io.ReadWriter) error
}

// ListenAndServe listens on the network address and then calls Serve
func ListenAndServe(network, address string) error {
	return NewServer().ListenAndServe(network, address)
}

// ListenAndServeWithAuth listens on the network address and then calls Serve
func ListenAndServeWithAuth(network, address string, userPW map[string]string) error {
	return NewServerWithAuth(userPW).ListenAndServe(network, address)
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
func NewServerWithAuth(userPW map[string]string) *Server {
	return &Server{
		SelectMethod: SelectMethodUsernamePassword,
		Authenticate: func(ctx context.Context, auth *Authentication) bool {
			pw, ok := userPW[string(auth.Username)]
			return ok && pw == string(auth.Password)
		},
	}
}

// ListenAndServe listens on the network address and then calls Serve
func (s *Server) ListenAndServe(network, address string) error {
	l, err := net.Listen(network, address)
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
	err := s.handle(ctx, conn)
	if err != nil {
		if s.Logger != nil {
			s.Logger(err)
		} else {
			//log.Println(err)
		}
	}
}

func (s *Server) handle(ctx context.Context, conn io.ReadWriteCloser) (err error) {
	// Select method
	var m Method
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
		var auth *Authentication
		auth, err = readAuthentication(conn)
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
	default:
		return fmt.Errorf("%w : %02x", ErrMethodNoAcceptable, m)
	}

	// Handle request
	var req *Request
	var reply Reply
	var bind *Address
	var target io.ReadWriteCloser
	req, err = readRequest(conn)
	if err != nil {
		return
	}
	if s.HandleRequest != nil {
		reply, bind, target = s.HandleRequest(ctx, req)
	} else {
		reply, bind, target = HandleRequest(ctx, req)
	}
	err = sendReply(conn, reply, bind)
	if err != nil {
		return
	}
	if reply != ReplySucceed {
		return fmt.Errorf("Reply : %s", reply.String())
	}

	// Start Proxy
	defer target.Close()
	if s.HandleProxy != nil {
		err = s.HandleProxy(ctx, conn, target)
	} else {
		err = HandleProxy(ctx, conn, target)
	}
	return err
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

// SelectMethodUsernamePassword only support username/password method
func SelectMethodUsernamePassword(ctx context.Context, methods []Method) Method {
	for _, m := range methods {
		if m == MethodUsernamePassword {
			return m
		}
	}
	return MethodNoAcceptable
}

// HandleRequest is the default value of Server.HandleRequest
func HandleRequest(ctx context.Context, req *Request) (
	reply Reply, bind *Address, target io.ReadWriteCloser) {
	reply = ReplyFailure
	switch req.Cmd {
	case CmdConnect:
		return handleConnect(req.Addr.String())
	case CmdBind:
		reply = ReplyCommandNotSupported
	case CmdUDP:
		reply = ReplyCommandNotSupported
	default:
		reply = ReplyCommandNotSupported
	}
	return
}

func handleConnect(addr string) (
	reply Reply, bind *Address, target io.ReadWriteCloser) {
	conn, err := net.Dial("tcp", addr)
	if err != nil {
		reply = ReplyHostUnreachable
		return
	}
	bind, err = NewAddress(conn.LocalAddr().String())
	if err != nil {
		reply = ReplyAddressNotSupported
		return
	}
	target = conn
	return
}

// HandleProxy is the default value of Server.HandleProxy
func HandleProxy(ctx context.Context,
	conn io.ReadWriter, target io.ReadWriter) (err error) {
	errCh := make(chan error, 2)
	go func() {
		_, e := io.Copy(conn, target)
		errCh <- e
	}()
	go func() {
		_, e := io.Copy(target, conn)
		errCh <- e
	}()

	select {
	case err = <-errCh:
	case <-ctx.Done():
		err = ctx.Err()
	}
	return
}
