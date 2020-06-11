package socks5

import (
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ReplyCode represents a SOCKS command reply code.
type ReplyCode byte

// Various Reply constants
const (
	ReplySucceed              ReplyCode = 0x00
	ReplyGeneralFailure       ReplyCode = 0x01
	ReplyConnectionNotAllowed ReplyCode = 0x02
	ReplyNetworkUnreachable   ReplyCode = 0x03
	ReplyHostUnreachable      ReplyCode = 0x04
	ReplyConnectionRefused    ReplyCode = 0x05
	ReplyTTLExpired           ReplyCode = 0x06
	ReplyCommandNotSupported  ReplyCode = 0x07
	ReplyAddressNotSupported  ReplyCode = 0x08
	ReplyFailure              ReplyCode = 0xff
)

// ErrReplyFailure represents reply failed
var ErrReplyFailure = errors.New("reply failure")

func (code ReplyCode) String() string {
	switch code {
	case ReplySucceed:
		return "succeeded"
	case ReplyGeneralFailure:
		return "general SOCKS server failure"
	case ReplyConnectionNotAllowed:
		return "connection not allowed by ruleset"
	case ReplyNetworkUnreachable:
		return "network unreachable"
	case ReplyHostUnreachable:
		return "host unreachable"
	case ReplyConnectionRefused:
		return "connection refused"
	case ReplyTTLExpired:
		return "TTL expired"
	case ReplyCommandNotSupported:
		return "command not supported"
	case ReplyAddressNotSupported:
		return "address type not supported"
	default:
		return "unknown code: " + strconv.Itoa(int(code))
	}
}

// Reply has the detail of the reply message
type Reply struct {
	Ver  byte
	Code ReplyCode
	Bnd  Address
}

func newReply(code ReplyCode, addr string) (*Reply, error) {
	a, err := NewAddress(addr)
	if err != nil {
		return nil, err
	}
	return &Reply{
		Ver:  Version5,
		Code: code,
		Bnd:  *a,
	}, nil
}

func readReply(r io.Reader) (*Reply, error) {
	buf := []byte{0, 0, 0}
	_, err := io.ReadFull(r, buf)
	if err != nil {
		return nil, err
	}
	if buf[0] != Version5 {
		return nil, fmt.Errorf("%w : %02x", ErrInvalidVersion, buf[0])
	}
	bnd, err := readAddress(r)
	if err != nil {
		return nil, err
	}
	return &Reply{
		Ver:  buf[0],
		Code: ReplyCode(buf[1]),
		Bnd:  *bnd,
	}, nil
}

func (rep *Reply) send(w io.Writer) (err error) {
	_, err = w.Write([]byte{Version5, byte(rep.Code), Reserved})
	if err != nil {
		return
	}
	return rep.Bnd.send(w)
}

func getReplyCode(msg string) ReplyCode {
	if strings.Contains(msg, "refused") {
		return ReplyConnectionRefused
	}
	if strings.Contains(msg, "unreachable") {
		return ReplyNetworkUnreachable
	}
	return ReplyHostUnreachable
}
