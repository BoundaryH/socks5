package socks5

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// AddrType represents address type
type AddrType byte

// Various constants
const (
	AddrTypeUnknown AddrType = 0x00
	AddrTypeIPv4    AddrType = 0x01
	AddrTypeDN      AddrType = 0x03
	AddrTypeIPv6    AddrType = 0x04
)

// Various errors
var (
	ErrBadAddressType    = errors.New("bad address type")
	ErrInvalidIPv4       = errors.New("invalid IPv4 address")
	ErrInvalidIPv6       = errors.New("invalid IPv6 address")
	ErrInvalidDomainName = errors.New("invalid domain name")
	ErrInvalidPort       = errors.New("invalid port")
)

// Address is the address of socks5 protocol
type Address struct {
	Type   AddrType
	Domain string
	IP     net.IP
	Port   uint16
}

// NewAddress return the Address
func NewAddress(address string) (*Address, error) {
	host, port, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	p, err := strconv.ParseUint(port, 10, 16)
	if err != nil {
		return nil, fmt.Errorf("%w : %s", ErrInvalidPort, port)
	}
	ip := net.ParseIP(host)
	if ip == nil {
		d := []byte(host)
		if len(d) == 0 || len(d) > 255 {
			return nil, fmt.Errorf("%w : %s", ErrInvalidDomainName, host)
		}
		return &Address{
			Type:   AddrTypeDN,
			Domain: host,
			Port:   uint16(p),
		}, nil
	}
	if ip.To4() != nil {
		return &Address{
			Type: AddrTypeIPv4,
			IP:   ip,
			Port: uint16(p),
		}, nil
	}
	if ip.To16() != nil {
		return &Address{
			Type: AddrTypeIPv6,
			IP:   ip,
			Port: uint16(p),
		}, nil
	}
	return nil, ErrBadAddressType
}

func readAddress(r io.Reader) (*Address, error) {
	var a Address
	aType, err := readSingleByte(r)
	a.Type = AddrType(aType)
	if err != nil {
		return nil, err
	}

	switch a.Type {
	case AddrTypeIPv4:
		addr := make([]byte, net.IPv4len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		a.IP = net.IP(addr[:net.IPv4len])
	case AddrTypeIPv6:
		addr := make([]byte, net.IPv6len)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		a.IP = net.IP(addr[:net.IPv6len])
	case AddrTypeDN:
		l, err := readSingleByte(r)
		if err != nil {
			return nil, err
		}
		addr := make([]byte, l)
		if _, err := io.ReadFull(r, addr); err != nil {
			return nil, err
		}
		a.Domain = string(addr[:l])
	default:
		return nil, fmt.Errorf("%w : %2x", ErrBadAddressType, a.Type)
	}

	port := []byte{0, 0}
	if _, err := io.ReadFull(r, port); err != nil {
		return nil, err
	}
	a.Port = binary.BigEndian.Uint16(port)
	return &a, nil
}

func (a *Address) send(w io.Writer) error {
	buf := make([]byte, 1, 1+256+2)
	buf[0] = byte(a.Type)

	switch a.Type {
	case AddrTypeIPv4:
		ipv4 := a.IP.To4()
		if ipv4 == nil {
			return ErrInvalidIPv4
		}
		buf = append(buf, ipv4...)
	case AddrTypeIPv6:
		ipv6 := a.IP.To16()
		if ipv6 == nil {
			return ErrInvalidIPv6
		}
		buf = append(buf, ipv6...)
	case AddrTypeDN:
		domain := []byte(a.Domain)
		if len(domain) > 255 {
			return ErrInvalidDomainName
		}
		buf = append(buf, byte(len(domain)))
		buf = append(buf, domain...)
	default:
		return fmt.Errorf("%w : %2x", ErrBadAddressType, a.Type)
	}
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, a.Port)
	buf = append(buf, port...)

	_, err := w.Write(buf)
	return err
}

func (a *Address) String() string {
	switch a.Type {
	case AddrTypeIPv4, AddrTypeIPv6:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case AddrTypeDN:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	}
	return ""
}

// Host return the host string
func (a *Address) Host() string {
	switch a.Type {
	case AddrTypeIPv4, AddrTypeIPv6:
		return a.IP.String()
	case AddrTypeDN:
		return a.Domain
	}
	return ""
}
