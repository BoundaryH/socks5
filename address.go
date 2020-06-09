package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
)

// AddrType represents address type
type AddrType uint8

// Various constants
const (
	AddrTypeIPv4 AddrType = 0x01
	AddrTypeDN   AddrType = 0x03
	AddrTypeIPv6 AddrType = 0x04
)

// Various errors
var (
	ErrBadAddressType    = errors.New("bad address type")
	ErrInvalidIPv4       = errors.New("invalid IPv4 address")
	ErrInvalidIPv6       = errors.New("invalid IPv6 address")
	ErrInvalidDomainName = errors.New("invalid domain name")
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
		return nil, err
	}
	ip := net.ParseIP(host)
	if ip == nil {
		d := []byte(host)
		if len(d) > 255 {
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

// ReadAddress return the Address which read from reader
func ReadAddress(r io.Reader) (*Address, error) {
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

// ToByte return a slice of byte which is the address format of socks5
func (a *Address) ToByte() ([]byte, error) {
	var buf bytes.Buffer
	buf.WriteByte(byte(a.Type))

	switch a.Type {
	case AddrTypeIPv4:
		ipv4 := a.IP.To4()
		if ipv4 == nil {
			return nil, ErrInvalidIPv4
		}
		buf.Write(ipv4)
	case AddrTypeIPv6:
		ipv6 := a.IP.To16()
		if ipv6 == nil {
			return nil, ErrInvalidIPv6
		}
		buf.Write(ipv6)
	case AddrTypeDN:
		domain := []byte(a.Domain)
		if len(domain) > 255 {
			return nil, ErrInvalidDomainName
		}
		buf.WriteByte(byte(len(domain)))
		buf.Write(domain)
	default:
		return nil, fmt.Errorf("%w : %2x", ErrBadAddressType, a.Type)
	}
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, a.Port)
	buf.Write(port)
	return buf.Bytes(), nil
}

func (a *Address) String() string {
	switch a.Type {
	case AddrTypeIPv4:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	case AddrTypeDN:
		return fmt.Sprintf("%s:%d", a.Domain, a.Port)
	case AddrTypeIPv6:
		return fmt.Sprintf("%s:%d", a.IP.String(), a.Port)
	}
	return ""
}

// Equal reports whether a and b are the same address.
func (a *Address) Equal(b *Address) bool {
	if a.Type != b.Type || a.Port != b.Port {
		return false
	}
	if a.Type == AddrTypeDN {
		return a.Domain == b.Domain
	}
	return a.IP.Equal(b.IP)
}
