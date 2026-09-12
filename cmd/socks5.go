package main

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/binary"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/beevik/ntp"
)

// Magic addresses for UDP-over-TCP
const (
	UoTv1MagicAddress = "sp.udp-over-tcp.arpa"
	UoTv2MagicAddress = "sp.v2.udp-over-tcp.arpa"
)

// SOCKS5 constants
const (
	socksVersion5     = 0x05
	authMethodNone    = 0x00
	authMethodUserPass = 0x02
	authMethodNoAccept = 0xFF

	cmdConnect      = 0x01
	cmdUDPAssociate = 0x03

	atypIPv4   = 0x01
	atypDomain = 0x03
	atypIPv6   = 0x04

	// UoT v1 address types
	uot1AtypIPv4   = 0x00
	uot1AtypIPv6   = 0x01
	uot1AtypDomain = 0x02
)

// STUN constants
const (
	stunMagicCookie = 0x2112A442

	stunMsgBindingRequest  = 0x0001
	stunMsgBindingResponse = 0x0101

	stunAttrMappedAddress    = 0x0001
	stunAttrChangeRequest    = 0x0003
	stunAttrSourceAddress    = 0x0004
	stunAttrChangedAddress   = 0x0005
	stunAttrXorMappedAddress = 0x0020
	stunAttrResponseOrigin   = 0x802b
	stunAttrOtherAddress     = 0x802c
)

type socks5Config struct {
	address  string
	username string
	password string
}

type ProxyExitInfo struct {
	IP      string `json:"ip"`
	Country string `json:"country"`
	Region  string `json:"region"`
	City    string `json:"city"`
	ISP     string `json:"isp"`
	ASNOrg  string `json:"asn_organization"`
}

type TestResult struct {
	Name    string
	Success bool
	Error   error
	RTT     time.Duration
	Offset  time.Duration
	Stratum uint8
	Time    time.Time
	Details string
}

type DNSTestResult struct {
	Success    bool
	Error      error
	RTT        time.Duration
	ResolvedIP string
	Server     string
}

type ATYPTestResult struct {
	Success         bool
	IPSupported     bool
	IPRTT           time.Duration
	IPError         error
	DomainSupported bool
	DomainRTT       time.Duration
	DomainError     error
	Details         string
}

type NATTestResult struct {
	Success    bool
	Error      error
	NATType    string
	MappedIP   string
	MappedPort int
	Details    string
}

// DebugLogger prints debug messages when enabled
type DebugLogger struct {
	enabled bool
}

func (d *DebugLogger) Logf(format string, args ...any) {
	if d != nil && d.enabled {
		msg := fmt.Sprintf(format, args...)
		ts := time.Now().Format("15:04:05.000")
		fmt.Printf("[\033[36mDEBUG\033[0m %s] %s\n", ts, msg)
	}
}

// parseSocks5String parses various proxy string representations
func parseSocks5String(socks5Str string) (socks5Config, error) {
	var cfg socks5Config
	socks5Str = strings.TrimSpace(socks5Str)
	if socks5Str == "" {
		return cfg, fmt.Errorf("empty input string")
	}

	cleanStr := socks5Str
	if strings.HasPrefix(cleanStr, "socks5://") {
		cleanStr = strings.TrimPrefix(cleanStr, "socks5://")
	} else if strings.HasPrefix(cleanStr, "socks5:") {
		cleanStr = strings.TrimPrefix(cleanStr, "socks5:")
	}

	if strings.HasPrefix(socks5Str, "socks5://") {
		if parsed, err := url.Parse(socks5Str); err == nil && parsed.Host != "" {
			if _, port, err := net.SplitHostPort(parsed.Host); err == nil && isValidPort(port) {
				cfg.address = parsed.Host
				if parsed.User != nil {
					cfg.username = parsed.User.Username()
					cfg.password, _ = parsed.User.Password()
				}
				return cfg, nil
			}
		}
	}

	if atIdx := strings.LastIndex(cleanStr, "@"); atIdx != -1 {
		userInfo := cleanStr[:atIdx]
		hostPort := cleanStr[atIdx+1:]

		host, port, err := net.SplitHostPort(hostPort)
		if err != nil || !isValidPort(port) {
			return cfg, fmt.Errorf("invalid host:port after '@': %q", hostPort)
		}

		cfg.address = net.JoinHostPort(host, port)
		if u, p, found := strings.Cut(userInfo, ":"); found {
			cfg.username = u
			cfg.password = p
		} else {
			cfg.username = userInfo
		}
		return cfg, nil
	}

	if strings.HasPrefix(cleanStr, "[") {
		closeBracket := strings.Index(cleanStr, "]")
		if closeBracket != -1 && len(cleanStr) > closeBracket+1 && cleanStr[closeBracket+1] == ':' {
			host := cleanStr[1:closeBracket]
			remainder := cleanStr[closeBracket+2:]
			parts := strings.SplitN(remainder, ":", 3)
			if len(parts) >= 1 && isValidPort(parts[0]) {
				cfg.address = net.JoinHostPort(host, parts[0])
				if len(parts) == 3 {
					cfg.username = parts[1]
					cfg.password = parts[2]
				} else if len(parts) == 2 {
					cfg.username = parts[1]
				}
				return cfg, nil
			}
		}
	}

	parts := strings.Split(cleanStr, ":")
	switch len(parts) {
	case 2:
		if !isValidPort(parts[1]) {
			return cfg, fmt.Errorf("invalid port in %q", cleanStr)
		}
		cfg.address = fmt.Sprintf("%s:%s", parts[0], parts[1])
		return cfg, nil
	case 4:
		if !isValidPort(parts[1]) {
			return cfg, fmt.Errorf("invalid port in %q", cleanStr)
		}
		cfg.address = fmt.Sprintf("%s:%s", parts[0], parts[1])
		cfg.username = parts[2]
		cfg.password = parts[3]
		return cfg, nil
	case 3:
		if isValidPort(parts[1]) {
			cfg.address = fmt.Sprintf("%s:%s", parts[0], parts[1])
			cfg.username = parts[2]
			return cfg, nil
		}
	}

	patterns := []*regexp.Regexp{
		regexp.MustCompile(`^(?P<username>[^:]+):(?P<password>[^@]+)@(?P<host>[^:]+):(?P<port>\d+)$`),
		regexp.MustCompile(`^(?P<host>[^:]+):(?P<port>\d+):(?P<username>[^:]+):(?P<password>.+)$`),
		regexp.MustCompile(`^(?P<host>[^:]+):(?P<port>\d+)$`),
	}

	for _, pattern := range patterns {
		matches := pattern.FindStringSubmatch(cleanStr)
		if matches != nil {
			names := pattern.SubexpNames()
			result := make(map[string]string)
			for i, name := range names {
				if i != 0 && name != "" {
					result[name] = matches[i]
				}
			}
			if !isValidPort(result["port"]) {
				continue
			}
			cfg.address = fmt.Sprintf("%s:%s", result["host"], result["port"])
			cfg.username = result["username"]
			cfg.password = result["password"]
			return cfg, nil
		}
	}

	return cfg, fmt.Errorf("invalid SOCKS5 proxy string format: %q", socks5Str)
}

func isValidPort(portStr string) bool {
	p, err := strconv.Atoi(portStr)
	return err == nil && p > 0 && p <= 65535
}

// socks5Handshake performs SOCKS5 greeting and authentication
func socks5Handshake(conn net.Conn, username, password string, debug *DebugLogger) error {
	debug.Logf("Initiating SOCKS5 handshake...")

	var methods []byte
	if username != "" {
		methods = []byte{socksVersion5, 0x02, authMethodNone, authMethodUserPass}
		debug.Logf("Sending greeting with NO_AUTH (0x00) and USER_PASS (0x02)...")
	} else {
		methods = []byte{socksVersion5, 0x01, authMethodNone}
		debug.Logf("Sending greeting with NO_AUTH (0x00)...")
	}

	if _, err := conn.Write(methods); err != nil {
		return fmt.Errorf("failed to send SOCKS5 greeting: %w", err)
	}

	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		return fmt.Errorf("failed to read SOCKS5 greeting reply: %w", err)
	}

	if reply[0] != socksVersion5 {
		return fmt.Errorf("unsupported SOCKS version: 0x%02x (expected 0x05)", reply[0])
	}

	debug.Logf("Received greeting reply: VER=0x05, METHOD=0x%02x", reply[1])

	switch reply[1] {
	case authMethodNone:
		debug.Logf("No authentication required by server")
		return nil
	case authMethodUserPass:
		debug.Logf("Performing username/password authentication (RFC 1929)...")
		if username == "" {
			return errors.New("server requires authentication but no username provided")
		}

		var authBuf bytes.Buffer
		authBuf.WriteByte(0x01)
		authBuf.WriteByte(byte(len(username)))
		authBuf.WriteString(username)
		authBuf.WriteByte(byte(len(password)))
		authBuf.WriteString(password)

		if _, err := conn.Write(authBuf.Bytes()); err != nil {
			return fmt.Errorf("failed to send auth credentials: %w", err)
		}

		authReply := make([]byte, 2)
		if _, err := io.ReadFull(conn, authReply); err != nil {
			return fmt.Errorf("failed to read auth response: %w", err)
		}

		if authReply[1] != 0x00 {
			return fmt.Errorf("SOCKS5 authentication failed (status: 0x%02x)", authReply[1])
		}
		debug.Logf("Authentication successful")
		return nil
	case authMethodNoAccept:
		return errors.New("no acceptable authentication methods (0xFF)")
	default:
		return fmt.Errorf("unsupported authentication method chosen by server: 0x%02x", reply[1])
	}
}

// socks5Connect sends a SOCKS5 CONNECT command to the proxy
func socks5Connect(conn net.Conn, targetHost string, targetPort int, debug *DebugLogger) error {
	debug.Logf("Sending SOCKS5 CONNECT to %s:%d...", targetHost, targetPort)
	req := buildSocks5Request(cmdConnect, targetHost, targetPort)
	if _, err := conn.Write(req); err != nil {
		return fmt.Errorf("failed to send CONNECT request: %w", err)
	}

	bndAddr, bndPort, err := readSocks5Reply(conn, debug)
	if err != nil {
		return fmt.Errorf("SOCKS5 CONNECT failed: %w", err)
	}
	debug.Logf("SOCKS5 CONNECT established, bound to %s:%d", bndAddr, bndPort)
	return nil
}

func buildSocks5Request(cmd byte, targetHost string, targetPort int) []byte {
	var buf bytes.Buffer
	buf.WriteByte(socksVersion5)
	buf.WriteByte(cmd)
	buf.WriteByte(0x00) // RSV

	if ip := net.ParseIP(targetHost); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			buf.WriteByte(atypIPv4)
			buf.Write(ip4)
		} else {
			buf.WriteByte(atypIPv6)
			buf.Write(ip.To16())
		}
	} else {
		buf.WriteByte(atypDomain)
		buf.WriteByte(byte(len(targetHost)))
		buf.WriteString(targetHost)
	}

	portBytes := make([]byte, 2)
	binary.BigEndian.PutUint16(portBytes, uint16(targetPort))
	buf.Write(portBytes)
	return buf.Bytes()
}

func readSocks5Reply(r io.Reader, debug *DebugLogger) (string, int, error) {
	header := make([]byte, 4)
	if _, err := io.ReadFull(r, header); err != nil {
		return "", 0, fmt.Errorf("failed to read SOCKS5 reply header: %w", err)
	}

	ver, rep, atyp := header[0], header[1], header[3]
	if ver != socksVersion5 {
		return "", 0, fmt.Errorf("invalid SOCKS version in reply: 0x%02x", ver)
	}

	if rep != 0x00 {
		return "", 0, fmt.Errorf("SOCKS5 error: %s (code 0x%02x)", socks5RepString(rep), rep)
	}

	var bndAddr string
	switch atyp {
	case atypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		bndAddr = net.IP(ip).String()
	case atypDomain:
		lenBuf := make([]byte, 1)
		if _, err := io.ReadFull(r, lenBuf); err != nil {
			return "", 0, err
		}
		domain := make([]byte, lenBuf[0])
		if _, err := io.ReadFull(r, domain); err != nil {
			return "", 0, err
		}
		bndAddr = string(domain)
	case atypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(r, ip); err != nil {
			return "", 0, err
		}
		bndAddr = net.IP(ip).String()
	default:
		return "", 0, fmt.Errorf("unsupported ATYP in SOCKS5 reply: 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(r, portBuf); err != nil {
		return "", 0, err
	}
	bndPort := int(binary.BigEndian.Uint16(portBuf))

	return bndAddr, bndPort, nil
}

func socks5RepString(rep byte) string {
	switch rep {
	case 0x00:
		return "succeeded"
	case 0x01:
		return "general SOCKS server failure"
	case 0x02:
		return "connection not allowed by ruleset"
	case 0x03:
		return "network unreachable"
	case 0x04:
		return "host unreachable"
	case 0x05:
		return "connection refused"
	case 0x06:
		return "TTL expired"
	case 0x07:
		return "command not supported"
	case 0x08:
		return "address type not supported"
	default:
		return "unknown error"
	}
}

func splitHostPort(addr string, defaultPort int) (string, int, error) {
	if !strings.Contains(addr, ":") {
		return addr, defaultPort, nil
	}
	h, pStr, err := net.SplitHostPort(addr)
	if err != nil {
		return "", 0, err
	}
	p, err := strconv.Atoi(pStr)
	if err != nil {
		return "", 0, err
	}
	return h, p, nil
}

// -----------------------------------------------------------------------------
// Query Proxy Exit IP (via api.ip.sb / geoip)
// -----------------------------------------------------------------------------

func QueryProxyExitIP(cfg socks5Config, timeout time.Duration, debug *DebugLogger) (*ProxyExitInfo, error) {
	debug.Logf("--- [START] Querying Proxy Exit IP via ip.sb ---")

	dialContext := func(ctx context.Context, network, addr string) (net.Conn, error) {
		h, pStr, err := net.SplitHostPort(addr)
		if err != nil {
			return nil, err
		}
		p, err := strconv.Atoi(pStr)
		if err != nil {
			return nil, err
		}

		debug.Logf("Exit IP: dialing proxy %s to reach %s...", cfg.address, addr)
		conn, err := net.DialTimeout("tcp", cfg.address, timeout)
		if err != nil {
			return nil, fmt.Errorf("connect proxy failed: %w", err)
		}
		_ = conn.SetDeadline(time.Now().Add(timeout))

		if err := socks5Handshake(conn, cfg.username, cfg.password, debug); err != nil {
			conn.Close()
			return nil, err
		}

		if err := socks5Connect(conn, h, p, debug); err != nil {
			conn.Close()
			return nil, err
		}

		return conn, nil
	}

	client := &http.Client{
		Transport: &http.Transport{
			DialContext: dialContext,
		},
		Timeout: timeout,
	}

	// 1. Primary: https://api.ip.sb/geoip
	req, err := http.NewRequest("GET", "https://api.ip.sb/geoip", nil)
	if err == nil {
		req.Header.Set("User-Agent", "Mozilla/5.0 (compatible; socks5-udp-checker/1.1.0)")
		resp, err := client.Do(req)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var info ProxyExitInfo
			if err := json.NewDecoder(resp.Body).Decode(&info); err == nil && info.IP != "" {
				debug.Logf("Exit IP: successfully fetched via api.ip.sb/geoip: %s (%s, %s)", info.IP, info.Country, info.ISP)
				return &info, nil
			}
		} else if resp != nil {
			resp.Body.Close()
		}
	}

	// 2. Fallback: http://api.ip.sb/ip
	debug.Logf("Exit IP: trying fallback http://api.ip.sb/ip...")
	req2, err := http.NewRequest("GET", "http://api.ip.sb/ip", nil)
	if err == nil {
		req2.Header.Set("User-Agent", "curl/7.88.1")
		resp, err := client.Do(req2)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			body, _ := io.ReadAll(resp.Body)
			ipStr := strings.TrimSpace(string(body))
			if net.ParseIP(ipStr) != nil {
				debug.Logf("Exit IP: successfully fetched via api.ip.sb/ip: %s", ipStr)
				return &ProxyExitInfo{IP: ipStr}, nil
			}
		} else if resp != nil {
			resp.Body.Close()
		}
	}

	// 3. Fallback: http://ip-api.com/json/
	debug.Logf("Exit IP: trying fallback http://ip-api.com/json/...")
	req3, err := http.NewRequest("GET", "http://ip-api.com/json/", nil)
	if err == nil {
		resp, err := client.Do(req3)
		if err == nil && resp.StatusCode == http.StatusOK {
			defer resp.Body.Close()
			var raw struct {
				Query      string `json:"query"`
				Country    string `json:"country"`
				RegionName string `json:"regionName"`
				City       string `json:"city"`
				ISP        string `json:"isp"`
			}
			if err := json.NewDecoder(resp.Body).Decode(&raw); err == nil && raw.Query != "" {
				debug.Logf("Exit IP: successfully fetched via ip-api.com: %s", raw.Query)
				return &ProxyExitInfo{
					IP:      raw.Query,
					Country: raw.Country,
					Region:  raw.RegionName,
					City:    raw.City,
					ISP:     raw.ISP,
				}, nil
			}
		} else if resp != nil {
			resp.Body.Close()
		}
	}

	return nil, errors.New("failed to retrieve exit IP from all query services")
}

// -----------------------------------------------------------------------------
// SOCKS5 UDP Relay Dialing & Packaging
// -----------------------------------------------------------------------------

type atypMode int

const (
	atypAuto atypMode = iota
	atypForceIP
	atypForceDomain
)

type standardUDPConn struct {
	tcpConn   net.Conn
	udpConn   *net.UDPConn
	relayAddr *net.UDPAddr
	targetH   string
	targetP   int
	atyp      atypMode
	debug     *DebugLogger
}

func dialSocks5UDP(cfg socks5Config, targetHost string, targetPort int, timeout time.Duration, mode atypMode, debug *DebugLogger) (*standardUDPConn, error) {
	proxyHost, _, err := net.SplitHostPort(cfg.address)
	if err != nil {
		return nil, fmt.Errorf("invalid proxy address %q: %w", cfg.address, err)
	}

	debug.Logf("Connecting to proxy TCP %s...", cfg.address)
	tcpConn, err := net.DialTimeout("tcp", cfg.address, timeout)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
	}
	_ = tcpConn.SetDeadline(time.Now().Add(timeout))

	if err := socks5Handshake(tcpConn, cfg.username, cfg.password, debug); err != nil {
		tcpConn.Close()
		return nil, err
	}

	debug.Logf("Sending UDP ASSOCIATE request...")
	req := buildSocks5Request(cmdUDPAssociate, "0.0.0.0", 0)
	if _, err := tcpConn.Write(req); err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to send UDP ASSOCIATE request: %w", err)
	}

	bndAddr, bndPort, err := readSocks5Reply(tcpConn, debug)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("UDP ASSOCIATE rejected: %w", err)
	}
	debug.Logf("Relay reported BND.ADDR=%s:%d", bndAddr, bndPort)

	if bndAddr == "0.0.0.0" || bndAddr == "::" || bndAddr == "" {
		bndAddr = proxyHost
		debug.Logf("Replacing 0.0.0.0 with proxy host %s", bndAddr)
	}

	relayUDPAddr, err := net.ResolveUDPAddr("udp", net.JoinHostPort(bndAddr, strconv.Itoa(bndPort)))
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to resolve UDP relay address: %w", err)
	}

	udpConn, err := net.ListenUDP("udp", nil)
	if err != nil {
		tcpConn.Close()
		return nil, fmt.Errorf("failed to create local UDP socket: %w", err)
	}
	_ = udpConn.SetDeadline(time.Now().Add(timeout))

	return &standardUDPConn{
		tcpConn:   tcpConn,
		udpConn:   udpConn,
		relayAddr: relayUDPAddr,
		targetH:   targetHost,
		targetP:   targetPort,
		atyp:      mode,
		debug:     debug,
	}, nil
}

func (c *standardUDPConn) Read(b []byte) (n int, err error) {
	buf := make([]byte, 65535)
	nRead, srcAddr, err := c.udpConn.ReadFrom(buf)
	if err != nil {
		return 0, err
	}
	c.debug.Logf("Standard UDP: received %d bytes from relay %s", nRead, srcAddr.String())

	if nRead < 10 {
		return 0, fmt.Errorf("SOCKS5 UDP packet too short: %d bytes", nRead)
	}
	if buf[0] != 0 || buf[1] != 0 {
		return 0, fmt.Errorf("invalid RSV in SOCKS5 UDP header")
	}

	atyp := buf[3]
	headerLen := 4
	switch atyp {
	case atypIPv4:
		headerLen += 4 + 2
	case atypDomain:
		dlen := int(buf[4])
		headerLen += 1 + dlen + 2
	case atypIPv6:
		headerLen += 16 + 2
	default:
		return 0, fmt.Errorf("unknown ATYP 0x%02x in SOCKS5 UDP packet", atyp)
	}

	if nRead < headerLen {
		return 0, fmt.Errorf("SOCKS5 UDP packet shorter than header: %d < %d", nRead, headerLen)
	}

	payload := buf[headerLen:nRead]
	n = copy(b, payload)
	c.debug.Logf("Standard UDP: unwrapped payload (%d bytes)", n)
	return n, nil
}

func (c *standardUDPConn) Write(b []byte) (n int, err error) {
	return c.WriteToTarget(b, c.targetH, c.targetP)
}

func (c *standardUDPConn) WriteToTarget(b []byte, targetHost string, targetPort int) (n int, err error) {
	var packet bytes.Buffer
	packet.Write([]byte{0x00, 0x00, 0x00}) // RSV + FRAG

	if c.atyp == atypForceIP {
		ip := net.ParseIP(targetHost)
		if ip == nil {
			ips, err := net.LookupIP(targetHost)
			if err != nil || len(ips) == 0 {
				return 0, fmt.Errorf("failed to resolve %q locally for ATYP IPv4 test: %w", targetHost, err)
			}
			ip = ips[0]
			c.debug.Logf("ATYP Force IP: resolved %s -> %s", targetHost, ip.String())
		}
		if ip4 := ip.To4(); ip4 != nil {
			packet.WriteByte(atypIPv4)
			packet.Write(ip4)
		} else {
			packet.WriteByte(atypIPv6)
			packet.Write(ip.To16())
		}
	} else if c.atyp == atypForceDomain {
		packet.WriteByte(atypDomain)
		packet.WriteByte(byte(len(targetHost)))
		packet.WriteString(targetHost)
		c.debug.Logf("ATYP Force Domain: sending target %s as FQDN (0x03)", targetHost)
	} else {
		if ip := net.ParseIP(targetHost); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				packet.WriteByte(atypIPv4)
				packet.Write(ip4)
			} else {
				packet.WriteByte(atypIPv6)
				packet.Write(ip.To16())
			}
		} else {
			packet.WriteByte(atypDomain)
			packet.WriteByte(byte(len(targetHost)))
			packet.WriteString(targetHost)
		}
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(targetPort))
	packet.Write(portBuf)
	packet.Write(b)

	c.debug.Logf("Standard UDP: sending %d bytes (%d payload) to relay %s", packet.Len(), len(b), c.relayAddr.String())
	_, err = c.udpConn.WriteTo(packet.Bytes(), c.relayAddr)
	if err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *standardUDPConn) Close() error {
	var err1, err2 error
	if c.udpConn != nil {
		err1 = c.udpConn.Close()
	}
	if c.tcpConn != nil {
		err2 = c.tcpConn.Close()
	}
	if err1 != nil {
		return err1
	}
	return err2
}

func (c *standardUDPConn) LocalAddr() net.Addr                { return c.udpConn.LocalAddr() }
func (c *standardUDPConn) RemoteAddr() net.Addr               { return c.relayAddr }
func (c *standardUDPConn) SetDeadline(t time.Time) error      { return c.udpConn.SetDeadline(t) }
func (c *standardUDPConn) SetReadDeadline(t time.Time) error  { return c.udpConn.SetReadDeadline(t) }
func (c *standardUDPConn) SetWriteDeadline(t time.Time) error { return c.udpConn.SetWriteDeadline(t) }

// -----------------------------------------------------------------------------
// Standard SOCKS5 UDP Test (NTP)
// -----------------------------------------------------------------------------

func TestStandardUDP(cfg socks5Config, ntpServer string, timeout time.Duration, debug *DebugLogger) (*TestResult, error) {
	debug.Logf("--- [START] Testing Standard SOCKS5 UDP Associate ---")
	startTime := time.Now()

	ntpHost, ntpPort, err := splitHostPort(ntpServer, 123)
	if err != nil {
		return nil, fmt.Errorf("invalid NTP server %q: %w", ntpServer, err)
	}

	dialer := func(_, _ string) (net.Conn, error) {
		return dialSocks5UDP(cfg, ntpHost, ntpPort, timeout, atypAuto, debug)
	}

	debug.Logf("Standard UDP: querying NTP server %s...", ntpServer)
	resp, err := ntp.QueryWithOptions(ntpServer, ntp.QueryOptions{
		Timeout: timeout,
		Dialer:  dialer,
	})
	if err != nil {
		debug.Logf("Standard UDP test failed: %v", err)
		return &TestResult{
			Name:    "Standard SOCKS5 UDP (Port 123)",
			Success: false,
			Error:   err,
		}, err
	}

	rtt := resp.RTT
	if rtt <= 0 {
		rtt = time.Since(startTime)
	}

	debug.Logf("Standard UDP test SUCCESS: Stratum=%d, RTT=%v, Time=%v", resp.Stratum, rtt, resp.Time)
	return &TestResult{
		Name:    "Standard SOCKS5 UDP (Port 123)",
		Success: true,
		RTT:     rtt,
		Offset:  resp.ClockOffset,
		Stratum: resp.Stratum,
		Time:    resp.Time,
	}, nil
}

// -----------------------------------------------------------------------------
// DNS Query Test (UDP Port 53)
// -----------------------------------------------------------------------------

func TestDNSQuery(cfg socks5Config, dnsServer string, timeout time.Duration, debug *DebugLogger) (*DNSTestResult, error) {
	debug.Logf("--- [START] Testing DNS Resolution (UDP Port 53) ---")
	startTime := time.Now()

	dnsHost, dnsPort, err := splitHostPort(dnsServer, 53)
	if err != nil {
		return nil, fmt.Errorf("invalid DNS server %q: %w", dnsServer, err)
	}

	conn, err := dialSocks5UDP(cfg, dnsHost, dnsPort, timeout, atypAuto, debug)
	if err != nil {
		return &DNSTestResult{Success: false, Error: err, Server: dnsServer}, err
	}
	defer conn.Close()

	const queryDomain = "one.one.one.one"
	const queryID uint16 = 0x5a5a
	queryPacket := buildDNSQuery(queryDomain, queryID)

	debug.Logf("DNS: sending query for %s to %s:%d...", queryDomain, dnsHost, dnsPort)
	if _, err := conn.Write(queryPacket); err != nil {
		return &DNSTestResult{Success: false, Error: fmt.Errorf("send DNS query failed: %w", err), Server: dnsServer}, err
	}

	respBuf := make([]byte, 2048)
	_ = conn.SetDeadline(time.Now().Add(timeout))
	n, err := conn.Read(respBuf)
	if err != nil {
		return &DNSTestResult{Success: false, Error: fmt.Errorf("read DNS response failed: %w", err), Server: dnsServer}, err
	}

	resolvedIP, err := parseDNSResponse(respBuf[:n], queryID)
	if err != nil {
		return &DNSTestResult{Success: false, Error: fmt.Errorf("invalid DNS response: %w", err), Server: dnsServer}, err
	}

	rtt := time.Since(startTime)
	debug.Logf("DNS test SUCCESS: resolved %s -> %s in %v", queryDomain, resolvedIP.String(), rtt)
	return &DNSTestResult{
		Success:    true,
		RTT:        rtt,
		ResolvedIP: resolvedIP.String(),
		Server:     dnsServer,
	}, nil
}

func buildDNSQuery(domain string, id uint16) []byte {
	var buf bytes.Buffer
	hdr := make([]byte, 12)
	binary.BigEndian.PutUint16(hdr[0:2], id)
	binary.BigEndian.PutUint16(hdr[2:4], 0x0100)
	binary.BigEndian.PutUint16(hdr[4:6], 1)
	buf.Write(hdr)

	labels := strings.Split(domain, ".")
	for _, label := range labels {
		buf.WriteByte(byte(len(label)))
		buf.WriteString(label)
	}
	buf.WriteByte(0x00)

	tail := make([]byte, 4)
	binary.BigEndian.PutUint16(tail[0:2], 1)
	binary.BigEndian.PutUint16(tail[2:4], 1)
	buf.Write(tail)

	return buf.Bytes()
}

func parseDNSResponse(data []byte, expectedID uint16) (net.IP, error) {
	if len(data) < 12 {
		return nil, errors.New("DNS packet too short")
	}
	id := binary.BigEndian.Uint16(data[0:2])
	if id != expectedID {
		return nil, fmt.Errorf("transaction ID mismatch: got 0x%04x, expected 0x%04x", id, expectedID)
	}
	flags := binary.BigEndian.Uint16(data[2:4])
	if flags&0x8000 == 0 {
		return nil, errors.New("not a DNS response")
	}
	rcode := flags & 0x000F
	if rcode != 0 {
		return nil, fmt.Errorf("DNS error RCODE=%d", rcode)
	}
	ancount := binary.BigEndian.Uint16(data[6:8])
	if ancount == 0 {
		return nil, errors.New("DNS response contains 0 answers")
	}

	offset := 12
	for offset < len(data) {
		l := int(data[offset])
		if l == 0 {
			offset++
			break
		}
		offset += 1 + l
	}
	offset += 4

	for i := 0; i < int(ancount) && offset < len(data); i++ {
		if offset+2 <= len(data) && data[offset]&0xC0 == 0xC0 {
			offset += 2
		} else {
			for offset < len(data) {
				l := int(data[offset])
				if l == 0 {
					offset++
					break
				}
				offset += 1 + l
			}
		}

		if offset+10 > len(data) {
			break
		}
		atype := binary.BigEndian.Uint16(data[offset : offset+2])
		rdlen := int(binary.BigEndian.Uint16(data[offset+8 : offset+10]))
		offset += 10

		if atype == 1 && rdlen == 4 && offset+4 <= len(data) {
			return net.IP(data[offset : offset+4]), nil
		}
		offset += rdlen
	}

	return nil, errors.New("no IPv4 (A) record found in DNS answers")
}

// -----------------------------------------------------------------------------
// ATYP Remote Domain Resolution Test
// -----------------------------------------------------------------------------

func TestATYPResolution(cfg socks5Config, ntpServer string, timeout time.Duration, debug *DebugLogger) (*ATYPTestResult, error) {
	debug.Logf("--- [START] Testing ATYP Remote Domain vs IPv4 Resolution ---")
	result := &ATYPTestResult{}

	ntpHost, ntpPort, err := splitHostPort(ntpServer, 123)
	if err != nil {
		return nil, fmt.Errorf("invalid NTP server %q: %w", ntpServer, err)
	}

	debug.Logf("ATYP Test: Step 1 - testing IPv4 ATYP (0x01)...")
	startIP := time.Now()
	dialerIP := func(_, _ string) (net.Conn, error) {
		return dialSocks5UDP(cfg, ntpHost, ntpPort, timeout, atypForceIP, debug)
	}
	respIP, errIP := ntp.QueryWithOptions(ntpServer, ntp.QueryOptions{Timeout: timeout, Dialer: dialerIP})
	if errIP == nil && respIP != nil {
		result.IPSupported = true
		result.IPRTT = time.Since(startIP)
		debug.Logf("ATYP Test: IPv4 (0x01) SUCCESS in %v", result.IPRTT)
	} else {
		result.IPSupported = false
		result.IPError = errIP
		debug.Logf("ATYP Test: IPv4 (0x01) FAILED: %v", errIP)
	}

	debug.Logf("ATYP Test: Step 2 - testing Domain ATYP (0x03)...")
	startDomain := time.Now()
	dialerDomain := func(_, _ string) (net.Conn, error) {
		return dialSocks5UDP(cfg, ntpHost, ntpPort, timeout, atypForceDomain, debug)
	}
	respDomain, errDomain := ntp.QueryWithOptions(ntpServer, ntp.QueryOptions{Timeout: timeout, Dialer: dialerDomain})
	if errDomain == nil && respDomain != nil {
		result.DomainSupported = true
		result.DomainRTT = time.Since(startDomain)
		debug.Logf("ATYP Test: Domain (0x03) SUCCESS in %v", result.DomainRTT)
	} else {
		result.DomainSupported = false
		result.DomainError = errDomain
		debug.Logf("ATYP Test: Domain (0x03) FAILED: %v", errDomain)
	}

	if result.IPSupported && result.DomainSupported {
		result.Success = true
		result.Details = "Fully Supported (Proxy resolves domain names in UDP relay headers)"
	} else if result.IPSupported && !result.DomainSupported {
		result.Success = false
		result.Details = "Partial Support: Raw IPv4 works, but Domain (0x03) failed (Proxy lacks remote UDP domain resolution)"
	} else {
		result.Success = false
		result.Details = "Not Supported (Both IPv4 and Domain UDP relay failed)"
	}

	return result, nil
}

// -----------------------------------------------------------------------------
// NAT Type Detection (STUN - RFC 3489 / RFC 5389)
// -----------------------------------------------------------------------------

type stunResponse struct {
	mappedIP   string
	mappedPort int
	otherIP    string
	otherPort  int
	originIP   string
	originPort int
}

func TestNATType(cfg socks5Config, primarySTUN string, timeout time.Duration, debug *DebugLogger) (*NATTestResult, error) {
	debug.Logf("--- [START] Testing NAT Type (STUN) ---")

	stunHost, stunPort, err := splitHostPort(primarySTUN, 3478)
	if err != nil {
		return nil, fmt.Errorf("invalid STUN server %q: %w", primarySTUN, err)
	}

	conn, err := dialSocks5UDP(cfg, stunHost, stunPort, timeout, atypAuto, debug)
	if err != nil {
		return &NATTestResult{Success: false, Error: err, NATType: "UDP Blocked / Unavailable"}, err
	}
	defer conn.Close()

	debug.Logf("STUN: Sending Test 1 request to %s:%d...", stunHost, stunPort)
	tid1 := make([]byte, 12)
	_, _ = rand.Read(tid1)
	req1 := buildSTUNBindingRequest(tid1, false, false)

	if _, err := conn.Write(req1); err != nil {
		return &NATTestResult{Success: false, Error: err, NATType: "UDP Blocked"}, err
	}

	_ = conn.SetDeadline(time.Now().Add(timeout))
	respBuf := make([]byte, 2048)
	n1, err := conn.Read(respBuf)
	if err != nil {
		return &NATTestResult{
			Success: false,
			Error:   fmt.Errorf("STUN Test 1 timed out: %w", err),
			NATType: "UDP Blocked / Firewall Filtered",
		}, err
	}

	res1, err := parseSTUNResponse(respBuf[:n1], tid1)
	if err != nil {
		return &NATTestResult{Success: false, Error: err, NATType: "Unknown STUN Response"}, err
	}

	debug.Logf("STUN Test 1: Mapped=%s:%d, Other=%s:%d, Origin=%s:%d",
		res1.mappedIP, res1.mappedPort, res1.otherIP, res1.otherPort, res1.originIP, res1.originPort)

	mappedIP1 := res1.mappedIP
	mappedPort1 := res1.mappedPort

	debug.Logf("STUN: Sending Test 2 (Change-IP & Change-Port)...")
	tid2 := make([]byte, 12)
	_, _ = rand.Read(tid2)
	req2 := buildSTUNBindingRequest(tid2, true, true)

	_ = conn.SetDeadline(time.Now().Add(time.Duration(float64(timeout) * 0.7)))
	_, err2 := conn.Write(req2)
	if err2 == nil {
		n2, err2 := conn.Read(respBuf)
		if err2 == nil {
			res2, errParse := parseSTUNResponse(respBuf[:n2], tid2)
			if errParse == nil && res2 != nil {
				debug.Logf("STUN Test 2: Received response from different origin! Full Cone NAT detected.")
				return &NATTestResult{
					Success:    true,
					NATType:    "Full Cone NAT (NAT 1)",
					MappedIP:   mappedIP1,
					MappedPort: mappedPort1,
					Details:    "Full Cone: Outbound UDP allows all unsolicited inbound traffic; ideal for P2P/Gaming",
				}, nil
			}
		}
	}
	debug.Logf("STUN Test 2: No response from alternative IP/Port (Not Full Cone)")

	secondaryTarget := res1.otherIP
	secondaryPort := res1.otherPort
	if secondaryTarget == "" || secondaryPort == 0 {
		secondaryTarget = "stun.cloudflare.com"
		secondaryPort = 3478
	}

	debug.Logf("STUN: Sending Test 3 to secondary address %s:%d...", secondaryTarget, secondaryPort)
	tid3 := make([]byte, 12)
	_, _ = rand.Read(tid3)
	req3 := buildSTUNBindingRequest(tid3, false, false)

	_, err3 := conn.WriteToTarget(req3, secondaryTarget, secondaryPort)
	if err3 != nil {
		return &NATTestResult{
			Success:    true,
			NATType:    "Restricted Cone NAT (NAT 2/3)",
			MappedIP:   mappedIP1,
			MappedPort: mappedPort1,
			Details:    "Cone NAT: Failed secondary reachability test",
		}, nil
	}

	_ = conn.SetDeadline(time.Now().Add(time.Duration(float64(timeout) * 0.7)))
	n3, err3 := conn.Read(respBuf)
	if err3 != nil {
		debug.Logf("STUN Test 3 timed out against secondary target")
		return &NATTestResult{
			Success:    true,
			NATType:    "Port-Restricted Cone NAT (NAT 3)",
			MappedIP:   mappedIP1,
			MappedPort: mappedPort1,
			Details:    "Port-Restricted Cone: Inbound accepted only from contacted IP and Port",
		}, nil
	}

	res3, err3 := parseSTUNResponse(respBuf[:n3], tid3)
	if err3 != nil {
		return &NATTestResult{
			Success:    true,
			NATType:    "Restricted Cone NAT (NAT 2)",
			MappedIP:   mappedIP1,
			MappedPort: mappedPort1,
			Details:    "Cone NAT: Consistent mapped port",
		}, nil
	}

	debug.Logf("STUN Test 3: Second Mapped Address = %s:%d (First was %s:%d)",
		res3.mappedIP, res3.mappedPort, mappedIP1, mappedPort1)

	if res3.mappedPort != mappedPort1 || res3.mappedIP != mappedIP1 {
		debug.Logf("STUN: Mapped port changed across destinations! Symmetric NAT detected.")
		return &NATTestResult{
			Success:    true,
			NATType:    "Symmetric NAT (NAT 4)",
			MappedIP:   mappedIP1,
			MappedPort: mappedPort1,
			Details:    fmt.Sprintf("Symmetric: Mapped port changes per destination (%d -> %d); P2P direct connection restricted", mappedPort1, res3.mappedPort),
		}, nil
	}

	return &NATTestResult{
		Success:    true,
		NATType:    "Restricted Cone NAT (NAT 2)",
		MappedIP:   mappedIP1,
		MappedPort: mappedPort1,
		Details:    "Restricted Cone: Mapped address is consistent across different destinations",
	}, nil
}

func buildSTUNBindingRequest(tid []byte, changeIP, changePort bool) []byte {
	var buf bytes.Buffer
	msgType := uint16(stunMsgBindingRequest)
	magic := uint32(stunMagicCookie)

	var attrLen uint16
	if changeIP || changePort {
		attrLen = 8
	}

	hdr := make([]byte, 20)
	binary.BigEndian.PutUint16(hdr[0:2], msgType)
	binary.BigEndian.PutUint16(hdr[2:4], attrLen)
	binary.BigEndian.PutUint32(hdr[4:8], magic)
	copy(hdr[8:20], tid)
	buf.Write(hdr)

	if changeIP || changePort {
		attr := make([]byte, 8)
		binary.BigEndian.PutUint16(attr[0:2], stunAttrChangeRequest)
		binary.BigEndian.PutUint16(attr[2:4], 4)
		var val uint32
		if changeIP {
			val |= 0x04
		}
		if changePort {
			val |= 0x02
		}
		binary.BigEndian.PutUint32(attr[4:8], val)
		buf.Write(attr)
	}

	return buf.Bytes()
}

func parseSTUNResponse(data []byte, expectedTID []byte) (*stunResponse, error) {
	if len(data) < 20 {
		return nil, errors.New("STUN packet too short")
	}

	msgType := binary.BigEndian.Uint16(data[0:2])
	if msgType != stunMsgBindingResponse {
		return nil, fmt.Errorf("unexpected STUN message type: 0x%04x", msgType)
	}

	res := &stunResponse{}
	offset := 20
	msgLen := int(binary.BigEndian.Uint16(data[2:4]))
	end := 20 + msgLen
	if end > len(data) {
		end = len(data)
	}

	for offset+4 <= end {
		attrType := binary.BigEndian.Uint16(data[offset : offset+2])
		attrLen := int(binary.BigEndian.Uint16(data[offset+2 : offset+4]))
		offset += 4

		if offset+attrLen > len(data) {
			break
		}
		val := data[offset : offset+attrLen]

		switch attrType {
		case stunAttrMappedAddress:
			if len(val) >= 8 && val[1] == 0x01 {
				port := binary.BigEndian.Uint16(val[2:4])
				ip := net.IP(val[4:8]).String()
				res.mappedIP = ip
				res.mappedPort = int(port)
			}
		case stunAttrXorMappedAddress:
			if len(val) >= 8 && val[1] == 0x01 {
				port := binary.BigEndian.Uint16(val[2:4]) ^ 0x2112
				ipBytes := make([]byte, 4)
				ipUint := binary.BigEndian.Uint32(val[4:8]) ^ stunMagicCookie
				binary.BigEndian.PutUint32(ipBytes, ipUint)
				res.mappedIP = net.IP(ipBytes).String()
				res.mappedPort = int(port)
			}
		case stunAttrChangedAddress, stunAttrOtherAddress:
			if len(val) >= 8 && val[1] == 0x01 {
				port := binary.BigEndian.Uint16(val[2:4])
				ip := net.IP(val[4:8]).String()
				res.otherIP = ip
				res.otherPort = int(port)
			}
		case stunAttrSourceAddress, stunAttrResponseOrigin:
			if len(val) >= 8 && val[1] == 0x01 {
				port := binary.BigEndian.Uint16(val[2:4])
				ip := net.IP(val[4:8]).String()
				res.originIP = ip
				res.originPort = int(port)
			}
		}

		paddedLen := (attrLen + 3) &^ 3
		offset += paddedLen
	}

	if res.mappedIP == "" {
		return nil, errors.New("no mapped address found in STUN response")
	}

	return res, nil
}

// -----------------------------------------------------------------------------
// UDP over TCP v1 (sp.udp-over-tcp.arpa)
// -----------------------------------------------------------------------------

type uot1Conn struct {
	tcpConn net.Conn
	targetH string
	targetP int
	debug   *DebugLogger
}

func (c *uot1Conn) Read(b []byte) (n int, err error) {
	atypBuf := make([]byte, 1)
	if _, err := io.ReadFull(c.tcpConn, atypBuf); err != nil {
		return 0, fmt.Errorf("UoT v1: failed to read ATYP: %w", err)
	}
	atyp := atypBuf[0]

	switch atyp {
	case uot1AtypIPv4:
		ip := make([]byte, 4)
		if _, err := io.ReadFull(c.tcpConn, ip); err != nil {
			return 0, err
		}
	case uot1AtypIPv6:
		ip := make([]byte, 16)
		if _, err := io.ReadFull(c.tcpConn, ip); err != nil {
			return 0, err
		}
	case uot1AtypDomain:
		dlenBuf := make([]byte, 1)
		if _, err := io.ReadFull(c.tcpConn, dlenBuf); err != nil {
			return 0, err
		}
		domain := make([]byte, dlenBuf[0])
		if _, err := io.ReadFull(c.tcpConn, domain); err != nil {
			return 0, err
		}
	default:
		return 0, fmt.Errorf("UoT v1: unknown ATYP 0x%02x", atyp)
	}

	portBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, portBuf); err != nil {
		return 0, fmt.Errorf("UoT v1: failed to read port: %w", err)
	}

	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, lenBuf); err != nil {
		return 0, fmt.Errorf("UoT v1: failed to read payload length: %w", err)
	}
	payloadLen := int(binary.BigEndian.Uint16(lenBuf))

	c.debug.Logf("UoT v1: reading payload of %d bytes from TCP stream...", payloadLen)
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.tcpConn, payload); err != nil {
		return 0, fmt.Errorf("UoT v1: failed to read payload: %w", err)
	}

	n = copy(b, payload)
	c.debug.Logf("UoT v1: successfully received %d bytes NTP response", n)
	return n, nil
}

func (c *uot1Conn) Write(b []byte) (n int, err error) {
	var frame bytes.Buffer

	if ip := net.ParseIP(c.targetH); ip != nil {
		if ip4 := ip.To4(); ip4 != nil {
			frame.WriteByte(uot1AtypIPv4)
			frame.Write(ip4)
		} else {
			frame.WriteByte(uot1AtypIPv6)
			frame.Write(ip.To16())
		}
	} else {
		frame.WriteByte(uot1AtypDomain)
		frame.WriteByte(byte(len(c.targetH)))
		frame.WriteString(c.targetH)
	}

	portBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(portBuf, uint16(c.targetP))
	frame.Write(portBuf)

	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(b)))
	frame.Write(lenBuf)

	frame.Write(b)

	c.debug.Logf("UoT v1: sending %d-byte frame (%d payload) over TCP stream...", frame.Len(), len(b))
	if _, err := c.tcpConn.Write(frame.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *uot1Conn) Close() error                       { return c.tcpConn.Close() }
func (c *uot1Conn) LocalAddr() net.Addr                { return c.tcpConn.LocalAddr() }
func (c *uot1Conn) RemoteAddr() net.Addr               { return c.tcpConn.RemoteAddr() }
func (c *uot1Conn) SetDeadline(t time.Time) error      { return c.tcpConn.SetDeadline(t) }
func (c *uot1Conn) SetReadDeadline(t time.Time) error  { return c.tcpConn.SetReadDeadline(t) }
func (c *uot1Conn) SetWriteDeadline(t time.Time) error { return c.tcpConn.SetWriteDeadline(t) }

func TestUoTv1(cfg socks5Config, ntpServer string, timeout time.Duration, debug *DebugLogger) (*TestResult, error) {
	debug.Logf("--- [START] Testing UDP-over-TCP v1 (sp.udp-over-tcp.arpa) ---")
	startTime := time.Now()

	ntpHost, ntpPort, err := splitHostPort(ntpServer, 123)
	if err != nil {
		return nil, fmt.Errorf("invalid NTP server %q: %w", ntpServer, err)
	}

	dialer := func(_, _ string) (net.Conn, error) {
		debug.Logf("UoT v1: connecting to proxy TCP %s...", cfg.address)
		tcpConn, err := net.DialTimeout("tcp", cfg.address, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
		}
		_ = tcpConn.SetDeadline(time.Now().Add(timeout))

		if err := socks5Handshake(tcpConn, cfg.username, cfg.password, debug); err != nil {
			tcpConn.Close()
			return nil, err
		}

		debug.Logf("UoT v1: sending CONNECT to %s:53...", UoTv1MagicAddress)
		if err := socks5Connect(tcpConn, UoTv1MagicAddress, 53, debug); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("server rejected UoT v1 magic address: %w", err)
		}

		return &uot1Conn{
			tcpConn: tcpConn,
			targetH: ntpHost,
			targetP: ntpPort,
			debug:   debug,
		}, nil
	}

	debug.Logf("UoT v1: querying NTP server %s...", ntpServer)
	resp, err := ntp.QueryWithOptions(ntpServer, ntp.QueryOptions{
		Timeout: timeout,
		Dialer:  dialer,
	})
	if err != nil {
		debug.Logf("UoT v1 test failed: %v", err)
		return &TestResult{
			Name:    "UDP-over-TCP v1",
			Success: false,
			Error:   err,
		}, err
	}

	rtt := resp.RTT
	if rtt <= 0 {
		rtt = time.Since(startTime)
	}

	debug.Logf("UoT v1 test SUCCESS: Stratum=%d, RTT=%v, Time=%v", resp.Stratum, rtt, resp.Time)
	return &TestResult{
		Name:    "UDP-over-TCP v1",
		Success: true,
		RTT:     rtt,
		Offset:  resp.ClockOffset,
		Stratum: resp.Stratum,
		Time:    resp.Time,
	}, nil
}

// -----------------------------------------------------------------------------
// UDP over TCP v2 (sp.v2.udp-over-tcp.arpa)
// -----------------------------------------------------------------------------

type uot2Conn struct {
	tcpConn net.Conn
	debug   *DebugLogger
}

func (c *uot2Conn) Read(b []byte) (n int, err error) {
	lenBuf := make([]byte, 2)
	if _, err := io.ReadFull(c.tcpConn, lenBuf); err != nil {
		return 0, fmt.Errorf("UoT v2: failed to read payload length: %w", err)
	}
	payloadLen := int(binary.BigEndian.Uint16(lenBuf))

	c.debug.Logf("UoT v2: reading %d bytes payload from TCP stream...", payloadLen)
	payload := make([]byte, payloadLen)
	if _, err := io.ReadFull(c.tcpConn, payload); err != nil {
		return 0, fmt.Errorf("UoT v2: failed to read payload: %w", err)
	}

	n = copy(b, payload)
	c.debug.Logf("UoT v2: successfully received %d bytes NTP response", n)
	return n, nil
}

func (c *uot2Conn) Write(b []byte) (n int, err error) {
	var frame bytes.Buffer
	lenBuf := make([]byte, 2)
	binary.BigEndian.PutUint16(lenBuf, uint16(len(b)))
	frame.Write(lenBuf)
	frame.Write(b)

	c.debug.Logf("UoT v2: sending %d-byte frame (%d payload) over TCP stream...", frame.Len(), len(b))
	if _, err := c.tcpConn.Write(frame.Bytes()); err != nil {
		return 0, err
	}
	return len(b), nil
}

func (c *uot2Conn) Close() error                       { return c.tcpConn.Close() }
func (c *uot2Conn) LocalAddr() net.Addr                { return c.tcpConn.LocalAddr() }
func (c *uot2Conn) RemoteAddr() net.Addr               { return c.tcpConn.RemoteAddr() }
func (c *uot2Conn) SetDeadline(t time.Time) error      { return c.tcpConn.SetDeadline(t) }
func (c *uot2Conn) SetReadDeadline(t time.Time) error  { return c.tcpConn.SetReadDeadline(t) }
func (c *uot2Conn) SetWriteDeadline(t time.Time) error { return c.tcpConn.SetWriteDeadline(t) }

func TestUoTv2(cfg socks5Config, ntpServer string, timeout time.Duration, debug *DebugLogger) (*TestResult, error) {
	debug.Logf("--- [START] Testing UDP-over-TCP v2 (sp.v2.udp-over-tcp.arpa) ---")
	startTime := time.Now()

	ntpHost, ntpPort, err := splitHostPort(ntpServer, 123)
	if err != nil {
		return nil, fmt.Errorf("invalid NTP server %q: %w", ntpServer, err)
	}

	dialer := func(_, _ string) (net.Conn, error) {
		debug.Logf("UoT v2: connecting to proxy TCP %s...", cfg.address)
		tcpConn, err := net.DialTimeout("tcp", cfg.address, timeout)
		if err != nil {
			return nil, fmt.Errorf("failed to connect to SOCKS5 proxy: %w", err)
		}
		_ = tcpConn.SetDeadline(time.Now().Add(timeout))

		if err := socks5Handshake(tcpConn, cfg.username, cfg.password, debug); err != nil {
			tcpConn.Close()
			return nil, err
		}

		debug.Logf("UoT v2: sending CONNECT to %s:0...", UoTv2MagicAddress)
		if err := socks5Connect(tcpConn, UoTv2MagicAddress, 0, debug); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("server rejected UoT v2 magic address: %w", err)
		}

		debug.Logf("UoT v2: sending handshake header (isConnect=1, target=%s:%d)...", ntpHost, ntpPort)
		var hs bytes.Buffer
		hs.WriteByte(0x01)

		if ip := net.ParseIP(ntpHost); ip != nil {
			if ip4 := ip.To4(); ip4 != nil {
				hs.WriteByte(atypIPv4)
				hs.Write(ip4)
			} else {
				hs.WriteByte(atypIPv6)
				hs.Write(ip.To16())
			}
		} else {
			hs.WriteByte(atypDomain)
			hs.WriteByte(byte(len(ntpHost)))
			hs.WriteString(ntpHost)
		}

		portBuf := make([]byte, 2)
		binary.BigEndian.PutUint16(portBuf, uint16(ntpPort))
		hs.Write(portBuf)

		if _, err := tcpConn.Write(hs.Bytes()); err != nil {
			tcpConn.Close()
			return nil, fmt.Errorf("failed to write UoT v2 handshake header: %w", err)
		}

		return &uot2Conn{
			tcpConn: tcpConn,
			debug:   debug,
		}, nil
	}

	debug.Logf("UoT v2: querying NTP server %s...", ntpServer)
	resp, err := ntp.QueryWithOptions(ntpServer, ntp.QueryOptions{
		Timeout: timeout,
		Dialer:  dialer,
	})
	if err != nil {
		debug.Logf("UoT v2 test failed: %v", err)
		return &TestResult{
			Name:    "UDP-over-TCP v2",
			Success: false,
			Error:   err,
		}, err
	}

	rtt := resp.RTT
	if rtt <= 0 {
		rtt = time.Since(startTime)
	}

	debug.Logf("UoT v2 test SUCCESS: Stratum=%d, RTT=%v, Time=%v", resp.Stratum, rtt, resp.Time)
	return &TestResult{
		Name:    "UDP-over-TCP v2",
		Success: true,
		RTT:     rtt,
		Offset:  resp.ClockOffset,
		Stratum: resp.Stratum,
		Time:    resp.Time,
	}, nil
}
