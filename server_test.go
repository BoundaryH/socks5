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

	req, err := NewRequest("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	reply, bind, _ := HandleRequest(ctx, req)
	if reply != ReplySucceed || bind == nil {
		t.Fatal("Error")
	}

	req, err = NewRequest("tcp", "127.0.0.1:8")
	if err != nil {
		t.Fatal(err)
	}
	reply, bind, _ = HandleRequest(ctx, req)
	if reply == ReplySucceed || bind != nil {
		t.Fatal("Error")
	}

	req, err = NewRequest("udp", "127.0.0.1:8")
	if err != nil {
		t.Fatal(err)
	}
	reply, bind, _ = HandleRequest(ctx, req)
	if reply != ReplyCommandNotSupported || bind != nil {
		t.Fatal("Error")
	}
}
