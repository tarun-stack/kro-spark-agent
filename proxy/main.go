package main

import (
	"bufio"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/binary"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strings"
	"sync"
	"syscall"
	"time"
	"unsafe"

	"gopkg.in/yaml.v3"
)

const (
	SO_ORIGINAL_DST = 80
	SOL_IP          = 0
)

type DomainEntry struct {
	Host               string `yaml:"host"`
	Port               int    `yaml:"port"`
	Action             string `yaml:"action"` // "credential-replace" or "passthrough"
	InjectHeader       string `yaml:"inject_header,omitempty"`
	InjectHeaderPrefix string `yaml:"inject_header_prefix,omitempty"`
	InjectAuth         string `yaml:"inject_auth,omitempty"`
	InjectAuthUser     string `yaml:"inject_auth_user,omitempty"`
	CredentialEnv      string `yaml:"credential_env,omitempty"`
}

type Config struct {
	Mode      string           `yaml:"mode"` // "strict", "allow-everything", "block-unknown"
	Domains []DomainEntry `yaml:"domains"`
}

var (
	config   Config
	caKey    *ecdsa.PrivateKey
	caCert   *x509.Certificate
	caCertPEM []byte
	upstreamRootCAs *x509.CertPool
	certCache sync.Map
)

func main() {
	configPath := "/etc/proxy/config.yaml"
	if p := os.Getenv("PROXY_CONFIG"); p != "" {
		configPath = p
	}

	data, err := os.ReadFile(configPath)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to read config: %v\n", err)
		os.Exit(1)
	}
	if err := yaml.Unmarshal(data, &config); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to parse config: %v\n", err)
		os.Exit(1)
	}
	if config.Mode == "" {
		config.Mode = "strict"
	}
	for i := range config.Domains {
		if config.Domains[i].Port == 0 {
			config.Domains[i].Port = 443
		}
		if config.Domains[i].Action == "" {
			config.Domains[i].Action = "credential-replace"
		}
	}

	if err := loadCA(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load CA: %v\n", err)
		os.Exit(1)
	}
	if err := loadUpstreamRoots(); err != nil {
		fmt.Fprintf(os.Stderr, "Failed to load upstream root CAs: %v\n", err)
		os.Exit(1)
	}

	listenPort := getEnvInt("PROXY_PORT", 15001)

	ln, err := net.Listen("tcp", fmt.Sprintf(":%d", listenPort))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to listen on port %d: %v\n", listenPort, err)
		os.Exit(1)
	}
	fmt.Printf("Transparent proxy listening on :%d\n", listenPort)
	fmt.Printf("Mode: %s\n", config.Mode)
	fmt.Printf("Domains: %d entries\n", len(config.Domains))
	for _, e := range config.Domains {
		fmt.Printf("  %s:%d [%s]\n", e.Host, e.Port, e.Action)
	}

	sig := make(chan os.Signal, 1)
	signal.Notify(sig, syscall.SIGTERM, syscall.SIGINT)
	go func() {
		<-sig
		fmt.Println("Shutting down proxy")
		ln.Close()
		os.Exit(0)
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			fmt.Fprintf(os.Stderr, "Accept error: %v\n", err)
			continue
		}
		go handleConnection(conn)
	}
}

func loadCA() error {
	certDir := os.Getenv("CERT_DIR")
	if certDir == "" {
		certDir = "/certs"
	}

	keyData, err := os.ReadFile(certDir + "/ca-key.pem")
	if err != nil {
		return fmt.Errorf("read CA key: %w", err)
	}
	block, _ := pem.Decode(keyData)
	if block == nil {
		return fmt.Errorf("failed to decode CA key PEM")
	}
	parsed, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		// Fall back to SEC1 format
		parsed, err = x509.ParseECPrivateKey(block.Bytes)
		if err != nil {
			return fmt.Errorf("parse CA key: %w", err)
		}
	}
	ecKey, ok := parsed.(*ecdsa.PrivateKey)
	if !ok {
		return fmt.Errorf("CA key is not ECDSA")
	}
	caKey = ecKey

	certData, err := os.ReadFile(certDir + "/ca-cert.pem")
	if err != nil {
		return fmt.Errorf("read CA cert: %w", err)
	}
	caCertPEM = certData
	block, _ = pem.Decode(certData)
	if block == nil {
		return fmt.Errorf("failed to decode CA cert PEM")
	}
	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return fmt.Errorf("parse CA cert: %w", err)
	}
	caCert = cert

	return nil
}

func loadUpstreamRoots() error {
	pool, err := x509.SystemCertPool()
	if err != nil || pool == nil {
		pool = x509.NewCertPool()
	}

	if certFile := os.Getenv("SSL_CERT_FILE"); certFile != "" {
		data, err := os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("read SSL_CERT_FILE %s: %w", certFile, err)
		}
		if ok := pool.AppendCertsFromPEM(data); !ok {
			return fmt.Errorf("append certificates from %s", certFile)
		}
	}

	upstreamRootCAs = pool
	return nil
}

func handleConnection(conn net.Conn) {
	defer conn.Close()

	origIP, origPort, err := getOriginalDst(conn)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to get original dest: %v\n", err)
		return
	}

	// Set a short deadline to peek the first byte (handles server-speaks-first protocols like SSH)
	conn.SetReadDeadline(time.Now().Add(1 * time.Second))
	br := bufio.NewReader(conn)
	firstByte, err := br.Peek(1)
	conn.SetReadDeadline(time.Time{}) // clear deadline

	bufferedConn := &bufferedReadConn{Reader: br, Conn: conn}

	if err != nil {
		// Peek failed (timeout or EOF) — no client data to identify protocol
		if config.Mode == "allow-everything" {
			fmt.Printf("PASSTHROUGH: no client data from %s:%d (mode=allow-everything)\n", origIP, origPort)
			tunnel(bufferedConn, origIP, origPort)
			return
		}
		fmt.Printf("BLOCKED: no client data to %s:%d (mode=%s)\n", origIP, origPort, config.Mode)
		return
	}

	var hostname string

	if firstByte[0] == 0x16 {
		// TLS ClientHello
		hostname = extractSNI(br)
	} else if isHTTPMethod(firstByte[0]) {
		// Plain HTTP. The client has already sent its full request and is
		// now waiting for a response, so Peek(4096) would otherwise block
		// forever trying to fill the buffer past however many bytes the
		// client actually sent (almost always < 4096 for a header-only
		// GET/POST). Bound it with the same short-deadline trick used for
		// the first-byte peek above.
		conn.SetReadDeadline(time.Now().Add(1 * time.Second))
		hostname = extractHTTPHost(br)
		conn.SetReadDeadline(time.Time{})
	}

	if hostname == "" {
		if config.Mode == "allow-everything" {
			fmt.Printf("PASSTHROUGH: unknown protocol to %s:%d (mode=allow-everything)\n", origIP, origPort)
			tunnel(bufferedConn, origIP, origPort)
			return
		}
		fmt.Printf("BLOCKED: unknown protocol to %s:%d (mode=%s)\n", origIP, origPort, config.Mode)
		return
	}

	entry := findDomainEntry(hostname, origPort)
	if entry == nil {
		if config.Mode != "strict" {
			fmt.Printf("PASSTHROUGH: %s:%d (not in domains, mode=%s)\n", hostname, origPort, config.Mode)
			tunnel(bufferedConn, origIP, origPort)
			return
		}
		fmt.Printf("BLOCKED: %s:%d\n", hostname, origPort)
		return
	}

	fmt.Printf("ALLOWED: %s:%d [%s]\n", hostname, origPort, entry.Action)

	switch entry.Action {
	case "passthrough":
		tunnel(bufferedConn, origIP, origPort)
	case "credential-replace":
		credentialReplaceTLS(bufferedConn, hostname, origIP, origPort, entry)
	default:
		fmt.Printf("BLOCKED: %s:%d (unknown action %q)\n", hostname, origPort, entry.Action)
	}
}

func getOriginalDst(conn net.Conn) (net.IP, int, error) {
	tcpConn, ok := conn.(*net.TCPConn)
	if !ok {
		return nil, 0, fmt.Errorf("not a TCP connection")
	}

	raw, err := tcpConn.SyscallConn()
	if err != nil {
		return nil, 0, fmt.Errorf("syscall conn: %w", err)
	}

	var origAddr [16]byte
	var sockErr error

	err = raw.Control(func(fd uintptr) {
		addrLen := uint32(16)
		_, _, errno := syscall.Syscall6(
			syscall.SYS_GETSOCKOPT,
			fd,
			SOL_IP,
			SO_ORIGINAL_DST,
			uintptr(unsafe.Pointer(&origAddr)),
			uintptr(unsafe.Pointer(&addrLen)),
			0,
		)
		if errno != 0 {
			sockErr = fmt.Errorf("getsockopt SO_ORIGINAL_DST: %v", errno)
		}
	})
	if err != nil {
		return nil, 0, err
	}
	if sockErr != nil {
		return nil, 0, sockErr
	}

	// sockaddr_in: family(2) + port(2) + addr(4)
	port := int(binary.BigEndian.Uint16(origAddr[2:4]))
	ip := net.IPv4(origAddr[4], origAddr[5], origAddr[6], origAddr[7])

	return ip, port, nil
}

func extractSNI(br *bufio.Reader) string {
	// Peek enough for the TLS record header + handshake
	header, err := br.Peek(5)
	if err != nil || len(header) < 5 {
		return ""
	}

	// TLS record: type(1) + version(2) + length(2)
	if header[0] != 0x16 {
		return ""
	}
	recordLen := int(binary.BigEndian.Uint16(header[3:5]))
	if recordLen > 16384 || recordLen < 42 {
		return ""
	}

	// Peek the full record
	data, err := br.Peek(5 + recordLen)
	if err != nil {
		// Try with what we have
		data, _ = br.Peek(br.Buffered())
		if len(data) < 48 {
			return ""
		}
	}

	// Skip record header, parse handshake
	pos := 5
	if pos >= len(data) || data[pos] != 0x01 { // ClientHello
		return ""
	}
	pos += 4 // handshake type + length(3)

	// Skip client version
	pos += 2
	// Skip client random
	pos += 32

	if pos >= len(data) {
		return ""
	}

	// Skip session ID
	sessionIDLen := int(data[pos])
	pos += 1 + sessionIDLen

	if pos+2 > len(data) {
		return ""
	}

	// Skip cipher suites
	cipherLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2 + cipherLen

	if pos >= len(data) {
		return ""
	}

	// Skip compression methods
	compLen := int(data[pos])
	pos += 1 + compLen

	if pos+2 > len(data) {
		return ""
	}

	// Extensions length
	extLen := int(binary.BigEndian.Uint16(data[pos : pos+2]))
	pos += 2

	end := pos + extLen
	if end > len(data) {
		end = len(data)
	}

	// Parse extensions looking for SNI (type 0x0000)
	for pos+4 <= end {
		extType := binary.BigEndian.Uint16(data[pos : pos+2])
		extDataLen := int(binary.BigEndian.Uint16(data[pos+2 : pos+4]))
		pos += 4

		if extType == 0x0000 && pos+extDataLen <= end {
			// SNI extension
			sniData := data[pos : pos+extDataLen]
			if len(sniData) < 5 {
				break
			}
			// SNI list length (2) + type (1) + name length (2) + name
			nameLen := int(binary.BigEndian.Uint16(sniData[3:5]))
			if 5+nameLen <= len(sniData) {
				return string(sniData[5 : 5+nameLen])
			}
			break
		}
		pos += extDataLen
	}

	return ""
}

func extractHTTPHost(br *bufio.Reader) string {
	// Peek enough to find the Host header
	data, _ := br.Peek(4096)
	if len(data) == 0 {
		return ""
	}

	lines := strings.Split(string(data), "\r\n")
	for _, line := range lines[1:] {
		if line == "" {
			break
		}
		if strings.HasPrefix(strings.ToLower(line), "host:") {
			host := strings.TrimSpace(line[5:])
			// Remove port if present
			if idx := strings.LastIndex(host, ":"); idx != -1 {
				host = host[:idx]
			}
			return host
		}
	}
	return ""
}

func isHTTPMethod(b byte) bool {
	// First byte of common HTTP methods: G(ET), P(OST/UT/ATCH), H(EAD), D(ELETE), O(PTIONS), C(ONNECT)
	return b == 'G' || b == 'P' || b == 'H' || b == 'D' || b == 'O' || b == 'C'
}

func findDomainEntry(hostname string, port int) *DomainEntry {
	for i := range config.Domains {
		e := &config.Domains[i]
		if e.Host == hostname && e.Port == port {
			return e
		}
	}
	return nil
}

func certValidityDays() int {
	return getEnvInt("CERT_VALIDITY_DAYS", 365)
}

func getEnvInt(key string, defaultVal int) int {
	if v := os.Getenv(key); v != "" {
		var val int
		if _, err := fmt.Sscanf(v, "%d", &val); err == nil {
			return val
		}
	}
	return defaultVal
}

func tunnel(clientConn net.Conn, origIP net.IP, origPort int) {
	upstream, err := net.DialTimeout("tcp", fmt.Sprintf("%s:%d", origIP.String(), origPort), 10*time.Second)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Tunnel dial error: %v\n", err)
		return
	}
	defer upstream.Close()

	pipe(clientConn, upstream)
}

func credentialReplaceTLS(clientConn net.Conn, hostname string, origIP net.IP, origPort int, entry *DomainEntry) {
	cert, err := getCertForHost(hostname)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Failed to generate cert for %s: %v\n", hostname, err)
		return
	}

	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{*cert},
		NextProtos:   []string{"http/1.1"},
	}

	tlsConn := tls.Server(clientConn, tlsConfig)
	if err := tlsConn.Handshake(); err != nil {
		fmt.Fprintf(os.Stderr, "TLS handshake error for %s: %v\n", hostname, err)
		return
	}
	defer tlsConn.Close()

	// Connect to real upstream
	upstreamTLS, err := tls.DialWithDialer(
		&net.Dialer{Timeout: 10 * time.Second},
		"tcp",
		fmt.Sprintf("%s:%d", hostname, origPort),
		&tls.Config{
			ServerName: hostname,
			RootCAs:    upstreamRootCAs,
			NextProtos: []string{"http/1.1"},
		},
	)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Upstream TLS dial error for %s: %v\n", hostname, err)
		return
	}
	defer upstreamTLS.Close()

	// Proxy HTTP requests with credential injection
	clientBuf := bufio.NewReader(tlsConn)
	for {
		req, err := http.ReadRequest(clientBuf)
		if err != nil {
			if err != io.EOF {
				fmt.Fprintf(os.Stderr, "Read request error from %s: %v\n", hostname, err)
			}
			return
		}

		injectCredential(req, entry)

		req.URL.Scheme = ""
		req.URL.Host = ""
		if err := req.Write(upstreamTLS); err != nil {
			fmt.Fprintf(os.Stderr, "Write to upstream %s error: %v\n", hostname, err)
			return
		}

		resp, err := http.ReadResponse(bufio.NewReader(upstreamTLS), req)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Read response from %s error: %v\n", hostname, err)
			return
		}

		if err := resp.Write(tlsConn); err != nil {
			resp.Body.Close()
			return
		}
		resp.Body.Close()
	}
}

func injectCredential(req *http.Request, entry *DomainEntry) {
	if entry.InjectHeader != "" {
		val := os.Getenv(entry.CredentialEnv)
		if val != "" {
			req.Header.Set(entry.InjectHeader, entry.InjectHeaderPrefix+val)
		}
	} else if entry.InjectAuth == "basic" {
		token := os.Getenv(entry.CredentialEnv)
		if token != "" {
			user := entry.InjectAuthUser
			if user == "" {
				user = "x-access-token"
			}
			req.SetBasicAuth(user, token)
		}
	}
}

func getCertForHost(hostname string) (*tls.Certificate, error) {
	if cached, ok := certCache.Load(hostname); ok {
		return cached.(*tls.Certificate), nil
	}

	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: hostname},
		DNSNames:     []string{hostname},
		NotBefore:    time.Now().Add(-1 * time.Hour),
		NotAfter:     time.Now().Add(time.Duration(certValidityDays()) * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}

	certDER, err := x509.CreateCertificate(rand.Reader, template, caCert, &key.PublicKey, caKey)
	if err != nil {
		return nil, err
	}

	tlsCert := &tls.Certificate{
		Certificate: [][]byte{certDER},
		PrivateKey:  key,
	}

	certCache.Store(hostname, tlsCert)
	return tlsCert, nil
}

func pipe(a, b net.Conn) {
	done := make(chan struct{}, 2)
	cp := func(dst, src net.Conn) {
		io.Copy(dst, src)
		done <- struct{}{}
	}
	go cp(a, b)
	go cp(b, a)
	<-done
}

type bufferedReadConn struct {
	*bufio.Reader
	net.Conn
}

func (c *bufferedReadConn) Read(p []byte) (int, error) {
	return c.Reader.Read(p)
}
