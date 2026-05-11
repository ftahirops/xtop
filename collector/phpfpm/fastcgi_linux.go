//go:build linux

package phpfpm

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Minimal FastCGI client — enough to query PHP-FPM's `pm.status_path` over
// a Unix socket or TCP. We send one BEGIN_REQUEST + PARAMS (terminator) +
// empty STDIN, then read STDOUT until EOF.
//
// FastCGI spec: https://fast-cgi.github.io/spec
// Record header: version(1) type(1) requestId(2) contentLen(2) padLen(1) reserved(1)

const (
	fcgiVersion = 1

	fcgiBeginRequest = 1
	fcgiAbortRequest = 2
	fcgiEndRequest   = 3
	fcgiParams       = 4
	fcgiStdin        = 5
	fcgiStdout       = 6
	fcgiStderr       = 7

	fcgiResponder = 1
	fcgiKeepConn  = 0 // we close after each request
)

// fcgiQuery dials the given address and runs one FastCGI request whose
// SCRIPT_NAME/SCRIPT_FILENAME point at the status path. PHP-FPM intercepts
// these internally — no PHP code runs.
//
// Returns the response body (stdout) with HTTP headers stripped.
func fcgiQuery(addr, statusPath, query string, timeout time.Duration) ([]byte, error) {
	network, dial, err := splitAddr(addr)
	if err != nil {
		return nil, err
	}
	conn, err := net.DialTimeout(network, dial, timeout)
	if err != nil {
		return nil, err
	}
	defer conn.Close()
	_ = conn.SetDeadline(time.Now().Add(timeout))

	// BEGIN_REQUEST
	if err := writeBeginRequest(conn); err != nil {
		return nil, err
	}
	// PARAMS — set SCRIPT_FILENAME + SCRIPT_NAME + QUERY_STRING + REQUEST_METHOD
	params := map[string]string{
		"SCRIPT_FILENAME": statusPath,
		"SCRIPT_NAME":     statusPath,
		"QUERY_STRING":    query,
		"REQUEST_METHOD":  "GET",
		"SERVER_PROTOCOL": "HTTP/1.0",
		"GATEWAY_INTERFACE": "CGI/1.1",
		"REMOTE_ADDR":     "127.0.0.1",
		"CONTENT_LENGTH":  "0",
	}
	if err := writeParams(conn, params); err != nil {
		return nil, err
	}
	// PARAMS terminator (empty)
	if err := writeRecord(conn, fcgiParams, nil); err != nil {
		return nil, err
	}
	// STDIN (empty) — signals end of request body
	if err := writeRecord(conn, fcgiStdin, nil); err != nil {
		return nil, err
	}

	// Read response until END_REQUEST.
	var stdout bytes.Buffer
	for {
		recType, body, err := readRecord(conn)
		if err != nil {
			if err == io.EOF {
				break
			}
			return nil, err
		}
		switch recType {
		case fcgiStdout:
			stdout.Write(body)
		case fcgiStderr:
			// drop — we don't need PHP-FPM warnings
		case fcgiEndRequest:
			return stripCGIHeaders(stdout.Bytes()), nil
		}
	}
	return stripCGIHeaders(stdout.Bytes()), nil
}

// splitAddr converts "unix:/tmp/php-cgi-83.sock" or "127.0.0.1:9000" or
// "/tmp/php-cgi-83.sock" into a (network, addr) pair for net.Dial.
func splitAddr(a string) (string, string, error) {
	if a == "" {
		return "", "", fmt.Errorf("empty fpm listen address")
	}
	if strings.HasPrefix(a, "unix:") {
		return "unix", strings.TrimPrefix(a, "unix:"), nil
	}
	if strings.HasPrefix(a, "/") {
		return "unix", a, nil
	}
	// host:port or :port or just port
	if strings.Contains(a, ":") {
		if strings.HasPrefix(a, ":") {
			return "tcp", "127.0.0.1" + a, nil
		}
		return "tcp", a, nil
	}
	// bare port number
	return "tcp", "127.0.0.1:" + a, nil
}

func writeBeginRequest(w io.Writer) error {
	body := make([]byte, 8)
	binary.BigEndian.PutUint16(body[0:2], fcgiResponder)
	body[2] = fcgiKeepConn
	// body[3..7] = reserved (zero)
	return writeRecord(w, fcgiBeginRequest, body)
}

// writeParams encodes name/value pairs into one or more PARAMS records.
// FastCGI name-value pair length encoding: 1 byte if <128, else 4 bytes
// with high bit set.
func writeParams(w io.Writer, params map[string]string) error {
	var buf bytes.Buffer
	for k, v := range params {
		writeLen(&buf, len(k))
		writeLen(&buf, len(v))
		buf.WriteString(k)
		buf.WriteString(v)
	}
	// FastCGI record body max 65535 — our params fit easily.
	return writeRecord(w, fcgiParams, buf.Bytes())
}

func writeLen(w *bytes.Buffer, n int) {
	if n < 128 {
		w.WriteByte(byte(n))
		return
	}
	var b [4]byte
	binary.BigEndian.PutUint32(b[:], uint32(n)|0x80000000)
	w.Write(b[:])
}

func writeRecord(w io.Writer, typ byte, body []byte) error {
	// Pad to 8-byte boundary for cleanliness.
	pad := (8 - (len(body) % 8)) % 8
	hdr := make([]byte, 8)
	hdr[0] = fcgiVersion
	hdr[1] = typ
	binary.BigEndian.PutUint16(hdr[2:4], 1) // requestId
	binary.BigEndian.PutUint16(hdr[4:6], uint16(len(body)))
	hdr[6] = byte(pad)
	if _, err := w.Write(hdr); err != nil {
		return err
	}
	if len(body) > 0 {
		if _, err := w.Write(body); err != nil {
			return err
		}
	}
	if pad > 0 {
		if _, err := w.Write(make([]byte, pad)); err != nil {
			return err
		}
	}
	return nil
}

func readRecord(r io.Reader) (byte, []byte, error) {
	hdr := make([]byte, 8)
	if _, err := io.ReadFull(r, hdr); err != nil {
		return 0, nil, err
	}
	typ := hdr[1]
	contentLen := binary.BigEndian.Uint16(hdr[4:6])
	padLen := hdr[6]
	body := make([]byte, contentLen)
	if contentLen > 0 {
		if _, err := io.ReadFull(r, body); err != nil {
			return 0, nil, err
		}
	}
	if padLen > 0 {
		if _, err := io.ReadFull(r, make([]byte, padLen)); err != nil {
			return 0, nil, err
		}
	}
	return typ, body, nil
}

// stripCGIHeaders removes the CGI header block that FPM emits before
// the status body (Content-type, Cache-Control, etc.).
func stripCGIHeaders(b []byte) []byte {
	// Look for the blank line that separates headers from body. Both
	// CRLF-CRLF and LF-LF appear in the wild.
	if i := bytes.Index(b, []byte("\r\n\r\n")); i >= 0 {
		return b[i+4:]
	}
	if i := bytes.Index(b, []byte("\n\n")); i >= 0 {
		return b[i+2:]
	}
	return b
}
