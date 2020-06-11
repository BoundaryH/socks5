package socks5

import (
	"bytes"
	"fmt"
	"testing"
)

func TestReply(t *testing.T) {
	if err := testReply(ReplySucceed, "abc:80"); err != nil {
		t.Fatal(err)
	}
	if err := testReply(ReplyFailure, "0.0.0.0:0"); err != nil {
		t.Fatal(err)
	}
}

func testReply(code ReplyCode, addr string) error {
	var buf bytes.Buffer
	a, err := newReply(code, addr)
	if err != nil {
		return err
	}
	if err := a.send(&buf); err != nil {
		return err
	}
	b, err := readReply(&buf)
	if err != nil {
		return err
	}

	if a.Code != b.Code || a.Bnd.String() != b.Bnd.String() {
		return fmt.Errorf("Error")
	}
	return nil
}
