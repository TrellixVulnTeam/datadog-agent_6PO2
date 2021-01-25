package util

import (
	"encoding/binary"
	"net"
	"unsafe"
)

var (
	nativeEndian binary.ByteOrder
)

// In lack of binary.NativeEndian ...
func init() {
	var i int32 = 0x01020304
	u := unsafe.Pointer(&i)
	pb := (*byte)(u)
	b := *pb
	if b == 0x04 {
		nativeEndian = binary.LittleEndian
	} else {
		nativeEndian = binary.BigEndian
	}
}

// Address is an IP abstraction that is family (v4/v6) agnostic
type Address interface {
	Bytes() []byte
	WriteTo([]byte) int
	String() string
	IsLoopback() bool
}

// AddressFromNetIP returns an Address from a provided net.IP
func AddressFromNetIP(ip net.IP) Address {
	if v4 := ip.To4(); v4 != nil {
		var a v4Address
		copy(a[:], v4)
		return a
	}

	var a v6Address
	copy(a[:], ip)
	return a
}

// AddressFromString creates an Address using the string representation of an v4 IP
func AddressFromString(ip string) Address {
	return AddressFromNetIP(net.ParseIP(ip))
}

// NetIPFromAddress returns a net.IP from an Address
func NetIPFromAddress(addr Address) net.IP {
	return net.IP(addr.Bytes())
}

type v4Address [4]byte

// V4Address creates an Address using the uint32 representation of an v4 IP
func V4Address(ip uint32) Address {
	var a v4Address
	nativeEndian.PutUint32(a[:], ip)
	return a
}

// V4AddressFromBytes creates an Address using the byte representation of an v4 IP
func V4AddressFromBytes(buf []byte) Address {
	var a v4Address
	copy(a[:], buf)
	return a
}

// Bytes returns a byte array of the underlying array
func (a v4Address) Bytes() []byte {
	return a[:]
}

// WriteTo writes the address byte representation into the supplied buffer
func (a v4Address) WriteTo(b []byte) int {
	return copy(b, a[:])
}

// String returns the human readable string representation of an IP
func (a v4Address) String() string {
	return net.IPv4(a[0], a[1], a[2], a[3]).String()
}

// IsLoopback returns true if this address is the loopback address
func (a v4Address) IsLoopback() bool {
	return net.IP(a[:]).IsLoopback()
}

type v6Address [16]byte

// V6Address creates an Address using the uint128 representation of an v6 IP
func V6Address(low, high uint64) Address {
	var a v6Address
	nativeEndian.PutUint64(a[:8], high)
	nativeEndian.PutUint64(a[8:], low)
	return a
}

// V6AddressFromBytes creates an Address using the byte representation of an v6 IP
func V6AddressFromBytes(buf []byte) Address {
	var a v6Address
	copy(a[:], buf)
	return a
}

// Bytes returns a byte array of the underlying array
func (a v6Address) Bytes() []byte {
	return a[:]
}

// WriteTo writes the address byte representation into the supplied buffer
func (a v6Address) WriteTo(b []byte) int {
	return copy(b, a[:])
}

// String returns the human readable string representation of an IP
func (a v6Address) String() string {
	return net.IP(a[:]).String()
}

// IsLoopback returns true if this address is the loopback address
func (a v6Address) IsLoopback() bool {
	return net.IP(a[:]).IsLoopback()
}
