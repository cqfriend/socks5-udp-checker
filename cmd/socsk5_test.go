package main

import (
	"bytes"
	"encoding/binary"
	"io"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
)

func TestParseSocks5String(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected socks5Config
		hasErr   bool
	}{
		{
			name:  "username:password@host:port without scheme",
			input: "myuser:mypassword@banana.island.com:8080",
			expected: socks5Config{
				address:  "banana.island.com:8080",
				username: "myuser",
				password: "mypassword",
			},
		},
		{
			name:  "username@host:port without password",
			input: "myuser@banana.island.com:8080",
			expected: socks5Config{
				address:  "banana.island.com:8080",
				username: "myuser",
				password: "",
			},
		},
		{
			name:  "socks5 with host and port only",
			input: "socks5:banana.island.com:8080",
			expected: socks5Config{
				address:  "banana.island.com:8080",
				username: "",
				password: "",
			},
		},
		{
			name:  "socks5:// with host and port only",
			input: "socks5://mango.island.com:9090",
			expected: socks5Config{
				address:  "mango.island.com:9090",
				username: "",
				password: "",
			},
		},
		{
			name:  "socks5:// with colon-separated credentials",
			input: "socks5://apple.fiji.net:1234:tiger123:secretpaw",
			expected: socks5Config{
				address:  "apple.fiji.net:1234",
				username: "tiger123",
				password: "secretpaw",
			},
		},
		{
			name:  "socks5 with colon-separated credentials",
			input: "socks5:orange.bali.org:5678:elephant789:junglepass",
			expected: socks5Config{
				address:  "orange.bali.org:5678",
				username: "elephant789",
				password: "junglepass",
			},
		},
		{
			name:  "socks5:// with @ format",
			input: "socks5://dolphin456:oceanwave@grape.hawaii.net:3333",
			expected: socks5Config{
				address:  "grape.hawaii.net:3333",
				username: "dolphin456",
				password: "oceanwave",
			},
		},
		{
			name:  "socks5: with @ format",
			input: "socks5:dolphin456:oceanwave@grape.hawaii.net:3333",
			expected: socks5Config{
				address:  "grape.hawaii.net:3333",
				username: "dolphin456",
				password: "oceanwave",
			},
		},
		{
			name:  "host:port with credentials",
			input: "kiwi.newzealand.co.nz:8080:kiwiuser:kiwipass",
			expected: socks5Config{
				address:  "kiwi.newzealand.co.nz:8080",
				username: "kiwiuser",
				password: "kiwipass",
			},
		},
		{
			name:  "host:port without credentials",
			input: "kiwi.newzealand.co.nz:8080",
			expected: socks5Config{
				address:  "kiwi.newzealand.co.nz:8080",
				username: "",
				password: "",
			},
		},
		{
			name:  "IPv4 host:port with credentials",
			input: "1.2.3.4:1080:user:pass",
			expected: socks5Config{
				address:  "1.2.3.4:1080",
				username: "user",
				password: "pass",
			},
		},
		{
			name:  "IPv4 host:port",
			input: "127.0.0.1:1080",
			expected: socks5Config{
				address:  "127.0.0.1:1080",
				username: "",
				password: "",
			},
		},
		{
			name:     "empty string",
			input:    "",
			expected: socks5Config{},
			hasErr:   true,
		},
		{
			name:     "invalid format - missing port",
			input:    "socks5:hostname",
			expected: socks5Config{},
			hasErr:   true,
		},
		{
			name:     "invalid @ format with non-numeric port",
			input:    "socks5://user:pass@host:invalid",
			expected: socks5Config{},
			hasErr:   true,
		},
		{
			name:     "invalid port number > 65535",
			input:    "127.0.0.1:99999",
			expected: socks5Config{},
			hasErr:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseSocks5String(tt.input)

			if tt.hasErr {
				require.Error(t, err)
				return
			}

			require.NoError(t, err)
			require.Equal(t, tt.expected.address, result.address)
			require.Equal(t, tt.expected.username, result.username)
			require.Equal(t, tt.expected.password, result.password)
		})
	}
}

func TestMaskPassword(t *testing.T) {
	cfg := socks5Config{
		address:  "127.0.0.1:1080",
		username: "admin",
		password: "secretpassword",
	}
	masked := maskPassword(cfg)
	require.Equal(t, "admin:******@127.0.0.1:1080", masked)

	noPass := socks5Config{
		address:  "127.0.0.1:1080",
		username: "guest",
		password: "",
	}
	require.Equal(t, "guest@127.0.0.1:1080", maskPassword(noPass))

	noAuth := socks5Config{
		address: "127.0.0.1:1080",
	}
	require.Equal(t, "127.0.0.1:1080", maskPassword(noAuth))
}

// TestSOCKS5MockServer verifies handshake and commands using a mock in-memory TCP server
func TestSOCKS5MockServer(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)
	defer ln.Close()

	go func() {
		for {
			conn, err := ln.Accept()
			if err != nil {
				return
			}
			go handleMockSOCKS5(conn)
		}
	}()

	cfg := socks5Config{
		address:  ln.Addr().String(),
		username: "testuser",
		password: "testpass",
	}
	debug := &DebugLogger{enabled: false}

	// Test SOCKS5 handshake & connect
	conn, err := net.DialTimeout("tcp", cfg.address, 2*time.Second)
	require.NoError(t, err)
	defer conn.Close()

	err = socks5Handshake(conn, cfg.username, cfg.password, debug)
	require.NoError(t, err)

	err = socks5Connect(conn, UoTv2MagicAddress, 0, debug)
	require.NoError(t, err)
}

func handleMockSOCKS5(conn net.Conn) {
	defer conn.Close()

	// Read greeting
	greeting := make([]byte, 256)
	n, err := conn.Read(greeting)
	if err != nil || n < 3 || greeting[0] != 0x05 {
		return
	}

	// Request username/password auth
	_, _ = conn.Write([]byte{0x05, 0x02})

	// Read auth
	auth := make([]byte, 256)
	n, err = conn.Read(auth)
	if err != nil || n < 2 || auth[0] != 0x01 {
		return
	}
	ulen := int(auth[1])
	username := string(auth[2 : 2+ulen])
	plen := int(auth[2+ulen])
	password := string(auth[3+ulen : 3+ulen+plen])

	if username != "testuser" || password != "testpass" {
		_, _ = conn.Write([]byte{0x01, 0x01}) // auth failed
		return
	}
	_, _ = conn.Write([]byte{0x01, 0x00}) // auth success

	// Read command
	cmd := make([]byte, 256)
	n, err = conn.Read(cmd)
	if err != nil || n < 4 || cmd[0] != 0x05 {
		return
	}

	// Send success reply
	reply := []byte{0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x10, 0x00}
	_, _ = conn.Write(reply)

	// If it was UoT v2, expect handshake then echo back
	if strings.Contains(string(cmd), UoTv2MagicAddress) {
		// Read UoT v2 handshake
		hs := make([]byte, 256)
		_, _ = conn.Read(hs)

		// Echo back frames
		for {
			lenBuf := make([]byte, 2)
			if _, err := io.ReadFull(conn, lenBuf); err != nil {
				return
			}
			l := binary.BigEndian.Uint16(lenBuf)
			payload := make([]byte, l)
			if _, err := io.ReadFull(conn, payload); err != nil {
				return
			}
			_, _ = conn.Write(lenBuf)
			_, _ = conn.Write(payload)
		}
	}
}

func TestDNSQueryParsing(t *testing.T) {
	// 1. Test buildDNSQuery
	pkt := buildDNSQuery("one.one.one.one", 0x1234)
	require.True(t, len(pkt) > 12)
	require.Equal(t, uint16(0x1234), binary.BigEndian.Uint16(pkt[:2]))

	// 2. Test parseDNSResponse with a synthetic response
	// Header: ID=0x1234, Flags=0x8180 (Response, NoError), QDCOUNT=1, ANCOUNT=1, NSCOUNT=0, ARCOUNT=0
	var resp bytes.Buffer
	resp.Write([]byte{0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00})
	// Question: one.one.one.one, A, IN
	resp.Write([]byte{0x03, 'o', 'n', 'e', 0x03, 'o', 'n', 'e', 0x03, 'o', 'n', 'e', 0x03, 'o', 'n', 'e', 0x00})
	resp.Write([]byte{0x00, 0x01, 0x00, 0x01})
	// Answer: Pointer to name (0xc00c), Type A (0x0001), Class IN (0x0001), TTL (0x0000003c), RDLen (0x0004), IP (1.1.1.1)
	resp.Write([]byte{0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04, 1, 1, 1, 1})

	ip, err := parseDNSResponse(resp.Bytes(), 0x1234)
	require.NoError(t, err)
	require.Equal(t, "1.1.1.1", ip.String())
}

func TestSTUNPacketHandling(t *testing.T) {
	tid := []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}
	req := buildSTUNBindingRequest(tid, true, true)
	require.Equal(t, 28, len(req))
	require.Equal(t, uint16(0x0001), binary.BigEndian.Uint16(req[:2]))
	require.Equal(t, uint32(stunMagicCookie), binary.BigEndian.Uint32(req[4:8]))

	// Synthetic STUN Response:
	// Header: MsgType=0x0101, Length=12, MagicCookie=0x2112A442, TID=12 bytes
	var resp bytes.Buffer
	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], stunMsgBindingResponse)
	binary.BigEndian.PutUint16(hdr[2:4], 12)
	binary.BigEndian.PutUint32(hdr[4:8], stunMagicCookie)
	copy(hdr[8:20], tid)
	resp.Write(hdr)

	// Attr: XOR-MAPPED-ADDRESS (0x0020), len=8
	// Family=0x01 (IPv4), Port=51947 ^ 0x2112, IP=222.137.248.5 ^ 0x2112A442
	attr := make([]byte, 12)
	binary.BigEndian.PutUint16(attr[0:2], stunAttrXorMappedAddress)
	binary.BigEndian.PutUint16(attr[2:4], 8)
	attr[4] = 0x00
	attr[5] = 0x01 // IPv4
	binary.BigEndian.PutUint16(attr[6:8], 51947^0x2112)
	ipBytes := net.ParseIP("222.137.248.5").To4()
	ipUint := binary.BigEndian.Uint32(ipBytes) ^ stunMagicCookie
	binary.BigEndian.PutUint32(attr[8:12], ipUint)
	resp.Write(attr)

	res, err := parseSTUNResponse(resp.Bytes(), tid)
	require.NoError(t, err)
	require.Equal(t, "222.137.248.5", res.mappedIP)
	require.Equal(t, 51947, res.mappedPort)
}
