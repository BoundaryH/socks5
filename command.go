package socks5

import (
	"errors"
	"fmt"
)

// Command represents SOCKS5 Command
type Command byte

// Various const
const (
	CmdConnect Command = 0x01
	CmdBind    Command = 0x02
	CmdUDP     Command = 0x03
)

// ErrCmdUnsupported represents the command unsupported
var ErrCmdUnsupported = errors.New("command unsupported")

func getCommand(network string) (Command, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
		return CmdConnect, nil
	case "udp", "udp4", "udp6":
		return CmdUDP, nil
	}
	return 0, fmt.Errorf("network not implemented : %s", network)
}
