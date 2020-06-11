package socks5

import (
	"context"
	"net"
	"testing"
)

func TestHandleRequest(t *testing.T) {
	l, err := net.Listen("tcp", "127.0.0.1:")
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()

	req, err := newRequest("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err := HandleRequest(ctx, nil, req)
	if err != nil || reply.Code != ReplySucceed {
		t.Fatal("Error")
	}

	req, err = newRequest("tcp", "127.0.0.1:8")
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err = HandleRequest(ctx, nil, req)
	if err == nil {
		t.Fatal("Error")
	}

	req, err = newRequest("udp", "127.0.0.1:8")
	if err != nil {
		t.Fatal(err)
	}
	reply, _, err = HandleRequest(ctx, nil, req)
	if err == nil {
		t.Fatal("Error")
	}
}
