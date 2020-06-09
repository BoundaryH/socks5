package socks5

import (
	"errors"
	"strconv"
)

// Reply represents a SOCKS command reply code.
type Reply uint8

// Various Reply constants
const (
	ReplySucceed              Reply = 0x00
	ReplyGeneralFailure       Reply = 0x01
	ReplyConnectionNotAllowed Reply = 0x02
	ReplyNetworkUnreachable   Reply = 0x03
	ReplyHostUnreachable      Reply = 0x04
	ReplyConnectionRefused    Reply = 0x05
	ReplyTTLExpired           Reply = 0x06
	ReplyCommandNotSupported  Reply = 0x07
	ReplyAddressNotSupported  Reply = 0x08
	ReplyFailure              Reply = 0xff
)

// ErrReplyFailure represents reply failed
var ErrReplyFailure = errors.New("reply failure")

func (code Reply) String() string {
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
