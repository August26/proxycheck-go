package checker

import (
	"context"
	"errors"
	"fmt"
	"net"
	"time"
)

// supportsSocks5UDP attempts a minimal SOCKS5 handshake including UDP ASSOCIATE.
// If it succeeds through the basic command flow, we consider UDP "supported".
//
// NOTE: This is a light probe. We are not yet doing a full UDP round-trip
// (DNS query etc.). That can come later.
func supportsSocks5UDP(ctx context.Context, host string, port int, username, password string) bool {
	addr := fmt.Sprintf("%s:%d", host, port)

	dialer := net.Dialer{
		Timeout: 3 * time.Second,
	}
	conn, err := dialer.DialContext(ctx, "tcp", addr)
	if err != nil {
		return false
	}
	defer conn.Close()

	// 1. greeting
	// build methods:
	//   0x00 = no auth
	//   0x02 = username/password
	methods := []byte{0x00}
	useAuth := false
	if username != "" || password != "" {
		methods = append(methods, 0x02)
		useAuth = true
	}

	req := []byte{0x05, byte(len(methods))}
	req = append(req, methods...)
	if _, err := conn.Write(req); err != nil {
		return false
	}

	// server chooses method
	buf := make([]byte, 2)
	if _, err := conn.Read(buf); err != nil {
		return false
	}
	if len(buf) < 2 || buf[0] != 0x05 {
		return false
	}
	chosenMethod := buf[1]

	// 2. auth if required
	if useAuth && chosenMethod == 0x02 {
		if err := socks5UserPassAuth(conn, username, password); err != nil {
			return false
		}
	} else if chosenMethod == 0x00 {
		// no auth
	} else {
		// proxy requested something we don't support
		return false
	}

	// 3. send UDP ASSOCIATE command
	// VER=0x05 CMD=0x03 RSV=0x00 ATYP=0x01(IPv4) ADDR=0.0.0.0 PORT=0
	// We basically ask it to open a UDP relay.
	cmd := []byte{
		0x05,       // VER
		0x03,       // CMD = UDP ASSOCIATE
		0x00,       // RSV
		0x01,       // ATYP = IPv4 (we'll just say 0.0.0.0:0)
		0x00, 0x00, 0x00, 0x00, // ADDR = 0.0.0.0
		0x00, 0x00, // PORT = 0
	}

	if _, err := conn.Write(cmd); err != nil {
		return false
	}

	// 4. read reply
	// Expected reply format:
	// VER=0x05 REP=0x00 RSV=0x00 ATYP=... BND.ADDR ... BND.PORT ...
	reply := make([]byte, 10)
	n, err := conn.Read(reply)
	if err != nil {
		return false
	}
	if n < 4 {
		return false
	}
	if reply[0] != 0x05 {
		return false
	}
	rep := reply[1]
	if rep != 0x00 {
		// non-zero REP means failure
		return false
	}

	// If we got here, proxy accepted UDP ASSOCIATE.
	return true
}

func socks5UserPassAuth(conn net.Conn, username, password string) error {
	// Username/Password auth subnegotiation per RFC1929.
	// auth packet:
	// VER=0x01, ULEN, U, PLEN, P
	ulen := len(username)
	plen := len(password)
	if ulen > 255 || plen > 255 {
		return errors.New("username/password too long for socks5 auth")
	}
	req := []byte{
		0x01,
		byte(ulen),
	}
	req = append(req, []byte(username)...)
	req = append(req, byte(plen))
	req = append(req, []byte(password)...)

	if _, err := conn.Write(req); err != nil {
		return err
	}

	resp := make([]byte, 2)
	if _, err := conn.Read(resp); err != nil {
		return err
	}
	if len(resp) < 2 {
		return errors.New("short auth response")
	}
	if resp[0] != 0x01 {
		return errors.New("invalid auth response version")
	}
	if resp[1] != 0x00 {
		return errors.New("socks5 auth failed")
	}
	return nil
}
