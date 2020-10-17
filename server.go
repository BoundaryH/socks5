package socks5

import (
	"context"
	"fmt"
	"io"
	"net"
)

// Stage respresent stage of handle process
type Stage int

// Define Stage value
const (
	StageSelectMethod Stage = iota
	StageAuth
	StageHandleRequest
	StageReply
)

// Event defines process values of connection
type Event struct {
	Stage  Stage
	Method Method
	Auth   *Authentication
	Req    *Request
	Reply  *Reply
	Target io.ReadWriteCloser
}

// Server defines parameters for running an SOCKS5 server
type Server struct {
	SelectMethod func(ctx context.Context, methods []Method) Method

	// return true indicates success
	// return false, handshake will be abort
	Authenticate func(ctx context.Context, auth *Authentication) bool

	// if err != nil, target should be nil
	HandleRequest func(ctx context.Context, auth *Authentication, req *Request) (*Reply, io.ReadWriteCloser, error)
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

// NewHandShaker creates a new SOCKS5 Server only for handshake
func NewHandShaker() *Server {
	return &Server{
		SelectMethod:  SelectMethodNoRequired,
		HandleRequest: HandleRequestSkip,
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
		go func() {
			s.ServeConn(context.Background(), conn)
			//log.Println(err)
		}()
	}
}

// ServeConn accepts a connection and handle SOCKS5 request
func (s *Server) ServeConn(ctx context.Context, conn io.ReadWriteCloser) error {
	defer conn.Close()
	event, err := s.Handshake(ctx, conn)
	if err != nil {
		return err
	}
	// Start Proxy
	if event.Target != nil {
		defer event.Target.Close()
		return Pipe(ctx, conn, event.Target)
	}
	return nil
}

// Handshake accepts a connection and handle SOCKS5 handshake
func (s *Server) Handshake(ctx context.Context, conn io.ReadWriter) (event Event, err error) {
	isDone := func() bool {
		select {
		case <-ctx.Done():
			err = ctx.Err()
			return true
		default:
			// skip
		}
		return false
	}

	// Select method
	event.Stage = StageSelectMethod
	var methods []Method
	methods, err = readMethods(conn)
	if err != nil {
		return
	}
	if s.SelectMethod != nil {
		event.Method = s.SelectMethod(ctx, methods)
	} else {
		event.Method = SelectMethodNoRequired(ctx, methods)
	}
	err = sendMethodSelection(conn, event.Method)
	if err != nil {
		return
	}
	if isDone() {
		return
	}

	// Authenticate
	event.Stage = StageAuth
	switch event.Method {
	case MethodNotRequired:
	case MethodUsernamePassword:
		event.Auth, err = readAuth(conn)
		if err != nil {
			return
		}
		result := false
		if s.Authenticate != nil {
			result = s.Authenticate(ctx, event.Auth)
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
		err = fmt.Errorf("%w : %02x", ErrMethodNoAcceptable, event.Method)
		return
	}
	if isDone() {
		return
	}

	// Handle request
	event.Stage = StageHandleRequest
	event.Req, err = readRequest(conn)
	if err != nil {
		return
	}
	if s.HandleRequest != nil {
		event.Reply, event.Target, err = s.HandleRequest(ctx, event.Auth, event.Req)
	} else {
		event.Reply, event.Target, err = HandleRequest(ctx, event.Auth, event.Req)
	}
	if isDone() {
		return
	}

	// Reply
	event.Stage = StageReply
	if err != nil {
		if event.Reply == nil {
			event.Reply, _ = newReply(ReplyFailure, "0.0.0.0:0")
		}
		event.Reply.send(conn)
		return
	}

	if event.Reply == nil {
		err = fmt.Errorf("reply is nil")
		return
	}
	err = event.Reply.send(conn)
	if err != nil {
		return
	}
	if event.Reply.Code != ReplySucceed {
		err = fmt.Errorf("Reply : %s", event.Reply.Code.String())
		return
	}
	if isDone() {
		return
	}
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

// HandleRequestSkip skip handle request and return a reply
func HandleRequestSkip(ctx context.Context, auth *Authentication, req *Request) (
	*Reply, io.ReadWriteCloser, error) {
	reply, err := newReply(ReplySucceed, "0.0.0.0:0")
	return reply, nil, err
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
