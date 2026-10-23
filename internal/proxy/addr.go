package proxy

import (
	"encoding/binary"
	"fmt"
	"net"
	"strconv"
)

// socksAddress encodes a destination the way SOCKS5 does: a type byte, the
// address, then a big-endian port. Shadowsocks carries this layout inside its
// stream as the request, and Trojan carries it after its command byte, so both
// protocols share the encoder rather than each growing its own.
func socksAddress(host, port string) ([]byte, error) {
	portNum, err := strconv.Atoi(port)
	if err != nil || portNum < 0 || portNum > 65535 {
		return nil, fmt.Errorf("port %q is not a number in 0..65535", port)
	}

	var addr []byte
	if ip := net.ParseIP(host); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			addr = append([]byte{0x01}, ip4...)
		} else {
			addr = append([]byte{0x04}, ip.To16()...)
		}
	} else {
		if len(host) > 255 {
			return nil, fmt.Errorf("host name is longer than 255 bytes")
		}
		addr = append([]byte{0x03, byte(len(host))}, host...)
	}
	return binary.BigEndian.AppendUint16(addr, uint16(portNum)), nil
}
