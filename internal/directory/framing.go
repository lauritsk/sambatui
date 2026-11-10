package directory

import (
	"encoding/binary"
	"errors"
	"io"
	"net"

	"github.com/lauritsk/sambatui/internal/invariant"
)

// framedConn validates each BER envelope before go-ldap allocates its body.
// A single reader owns framing state; net.Conn still owns writes and deadlines.
type framedConn struct {
	net.Conn
	header         [6]byte
	headerOffset   int
	headerCount    int
	remainingBytes int
}

func (conn *framedConn) Read(target []byte) (int, error) {
	invariant.Require(conn.remainingBytes >= 0, "LDAP frame size underflow")
	invariant.Require(conn.headerOffset <= conn.headerCount, "LDAP header cursor overflow")
	if len(target) == 0 {
		return 0, nil
	}
	if conn.headerOffset == conn.headerCount && conn.remainingBytes == 0 {
		count, sizeBytes, err := readHeader(conn.Conn, conn.header[:], searchBytesMax)
		if err != nil {
			return 0, err
		}
		conn.headerOffset = 0
		conn.headerCount = count
		conn.remainingBytes = sizeBytes
	}
	if conn.headerOffset < conn.headerCount {
		count := copy(target, conn.header[conn.headerOffset:conn.headerCount])
		conn.headerOffset += count
		return count, nil
	}
	count, err := conn.Conn.Read(target[:min(len(target), conn.remainingBytes)])
	conn.remainingBytes -= count
	return count, err
}

// Reject indefinite and oversized lengths before allocation, on 32-bit too.
func readHeader(reader io.Reader, header []byte, sizeBytesMax int) (int, int, error) {
	invariant.Require(len(header) == 6, "LDAP frame requires six header bytes")
	invariant.Require(sizeBytesMax > 0, "LDAP frame limit must be positive")
	if _, err := io.ReadFull(reader, header[:2]); err != nil {
		return 0, 0, err
	}
	if header[0] != 0x30 {
		return 0, 0, errors.New("unexpected LDAP envelope")
	}
	count := 2
	sizeBytes := uint32(header[1])
	if header[1]&0x80 != 0 {
		lengthBytes := int(header[1] & 0x7f)
		if lengthBytes == 0 || lengthBytes > 4 {
			return 0, 0, errors.New("invalid LDAP message length")
		}
		var encoded [4]byte
		if _, err := io.ReadFull(reader, encoded[4-lengthBytes:]); err != nil {
			return 0, 0, err
		}
		copy(header[2:], encoded[4-lengthBytes:])
		count += lengthBytes
		sizeBytes = binary.BigEndian.Uint32(encoded[:])
	}
	if uint64(sizeBytes) > uint64(sizeBytesMax) {
		return 0, 0, errors.New("LDAP response exceeds frame safety limit")
	}
	return count, int(sizeBytes), nil
}
