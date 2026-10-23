package proxy

import (
	"bufio"
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hkdf"
	"crypto/md5"
	"crypto/rand"
	"crypto/sha1"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"golang.org/x/crypto/chacha20poly1305"

	"github.com/aqiyoung/skyward-kernel/internal/config"
)

// maxChunk is the largest payload one AEAD frame carries; the two-byte length
// field is what caps it, not a protocol constant.
const maxChunk = 0x3fff

// ssCipher is the key schedule and AEAD of one cipher name. The length is the
// salt length as well, which is why both live here.
type ssCipher struct {
	keyLen  int
	newAEAD func(key []byte) (cipher.AEAD, error)
}

func newAESGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	return cipher.NewGCM(block)
}

func newChaCha(key []byte) (cipher.AEAD, error) {
	return chacha20poly1305.New(key)
}

var ssCiphers = map[string]ssCipher{
	"aes-128-gcm":            {16, newAESGCM},
	"aes-192-gcm":            {24, newAESGCM},
	"aes-256-gcm":            {32, newAESGCM},
	"chacha20-ietf-poly1305": {32, newChaCha},
}

// shadowsocks dials an AEAD Shadowsocks server.
type shadowsocks struct {
	name       string
	serverAddr string
	cipher     ssCipher
	masterKey  []byte
	dialer     net.Dialer
}

func newShadowsocks(p config.Proxy) (Dialer, error) {
	name := strings.ToLower(strings.TrimSpace(p.Cipher))
	spec, ok := ssCiphers[name]
	if !ok {
		return nil, fmt.Errorf("proxy %q: cipher %q is not implemented", p.Name, p.Cipher)
	}
	return &shadowsocks{
		name:       p.Name,
		serverAddr: p.Address(),
		cipher:     spec,
		// Shadowsocks derives its master key from the password with the ad hoc
		// EVP_BytesToKey, not a real KDF; the standard is what the server does.
		masterKey: evpBytesToKey(p.Password, spec.keyLen),
		dialer:    net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second},
	}, nil
}

func (s *shadowsocks) Name() string { return s.name }
func (s *shadowsocks) Type() string { return "ss" }

func (s *shadowsocks) DialContext(ctx context.Context, network, addr string) (net.Conn, error) {
	if network != "tcp" && network != "tcp4" && network != "tcp6" {
		return nil, fmt.Errorf("ss: %s is not implemented", network)
	}
	host, port, err := splitHostPort(addr)
	if err != nil {
		return nil, err
	}
	request, err := socksAddress(host, port)
	if err != nil {
		return nil, err
	}

	raw, err := s.dialer.DialContext(ctx, "tcp", s.serverAddr)
	if err != nil {
		return nil, err
	}

	// The client's salt opens the stream; the key it derives covers writes only.
	writeSalt := make([]byte, s.cipher.keyLen)
	if _, err := rand.Read(writeSalt); err != nil {
		raw.Close()
		return nil, err
	}
	writeKey, err := hkdf.Key(sha1.New, s.masterKey, writeSalt, "ss-subkey", s.cipher.keyLen)
	if err != nil {
		raw.Close()
		return nil, err
	}
	writeAEAD, err := s.cipher.newAEAD(writeKey)
	if err != nil {
		raw.Close()
		return nil, err
	}
	if _, err := raw.Write(writeSalt); err != nil {
		raw.Close()
		return nil, err
	}

	c := &ssConn{
		Conn:       raw,
		reader:     bufio.NewReader(raw),
		cipher:     s.cipher,
		masterKey:  s.masterKey,
		writeAEAD:  writeAEAD,
		writeNonce: make([]byte, writeAEAD.NonceSize()),
	}
	if _, err := c.Write(request); err != nil {
		raw.Close()
		return nil, err
	}
	return c, nil
}

// ssConn is one Shadowsocks stream. Its two directions are independent: each
// carries its own salt and its own AEAD, which is why the read side is set up on
// the first read rather than up front.
type ssConn struct {
	net.Conn
	reader    *bufio.Reader
	cipher    ssCipher
	masterKey []byte

	readAEAD  cipher.AEAD
	readNonce []byte
	pending   []byte

	writeAEAD  cipher.AEAD
	writeNonce []byte
}

func (c *ssConn) Read(p []byte) (int, error) {
	if len(c.pending) > 0 {
		n := copy(p, c.pending)
		c.pending = c.pending[n:]
		return n, nil
	}
	if c.readAEAD == nil {
		if err := c.beginRead(); err != nil {
			return 0, err
		}
	}

	// One frame: a sealed two-byte length, then the sealed payload.
	sealedLen := make([]byte, 2+c.readAEAD.Overhead())
	if _, err := io.ReadFull(c.reader, sealedLen); err != nil {
		return 0, err
	}
	plainLen, err := c.readAEAD.Open(nil, c.readNonce, sealedLen, nil)
	if err != nil {
		return 0, fmt.Errorf("ss: frame length does not authenticate: %w", err)
	}
	increment(c.readNonce)

	size := int(binary.BigEndian.Uint16(plainLen))
	sealed := make([]byte, size+c.readAEAD.Overhead())
	if _, err := io.ReadFull(c.reader, sealed); err != nil {
		return 0, err
	}
	payload, err := c.readAEAD.Open(nil, c.readNonce, sealed, nil)
	if err != nil {
		return 0, fmt.Errorf("ss: frame payload does not authenticate: %w", err)
	}
	increment(c.readNonce)

	n := copy(p, payload)
	c.pending = payload[n:]
	return n, nil
}

// beginReadingWith opens the read side for a peer whose salt the caller already
// consumed and turned into a key. The client never needs it — its read side
// starts with a salt from the server — but a server, and the test that stands in
// for one, does.
func (c *ssConn) beginReadingWith(key []byte) error {
	aead, err := c.cipher.newAEAD(key)
	if err != nil {
		return err
	}
	c.readAEAD = aead
	c.readNonce = make([]byte, aead.NonceSize())
	return nil
}

// beginWritingAs opens the write side under a fresh salt and puts that salt on
// the wire, which is how the answering end of a stream starts.
func (c *ssConn) beginWritingAs(masterKey []byte) error {
	salt := make([]byte, c.cipher.keyLen)
	if _, err := rand.Read(salt); err != nil {
		return err
	}
	if _, err := c.Conn.Write(salt); err != nil {
		return err
	}
	key, err := hkdf.Key(sha1.New, masterKey, salt, "ss-subkey", c.cipher.keyLen)
	if err != nil {
		return err
	}
	aead, err := c.cipher.newAEAD(key)
	if err != nil {
		return err
	}
	c.writeAEAD = aead
	c.writeNonce = make([]byte, aead.NonceSize())
	return nil
}

func (c *ssConn) beginRead() error {
	salt := make([]byte, c.cipher.keyLen)
	if _, err := io.ReadFull(c.reader, salt); err != nil {
		return err
	}
	key, err := hkdf.Key(sha1.New, c.masterKey, salt, "ss-subkey", c.cipher.keyLen)
	if err != nil {
		return err
	}
	aead, err := c.cipher.newAEAD(key)
	if err != nil {
		return err
	}
	c.readAEAD = aead
	c.readNonce = make([]byte, aead.NonceSize())
	return nil
}

func (c *ssConn) Write(p []byte) (int, error) {
	written := 0
	for len(p) > 0 {
		size := min(len(p), maxChunk)
		chunk := p[:size]

		var lenBuf [2]byte
		binary.BigEndian.PutUint16(lenBuf[:], uint16(size))
		frame := c.writeAEAD.Seal(nil, c.writeNonce, lenBuf[:], nil)
		increment(c.writeNonce)
		frame = c.writeAEAD.Seal(frame, c.writeNonce, chunk, nil)
		increment(c.writeNonce)

		if _, err := c.Conn.Write(frame); err != nil {
			return written, err
		}
		written += size
		p = p[size:]
	}
	return written, nil
}

// increment walks the nonce as a little-endian integer, which is the order
// Shadowsocks AEAD counts in.
func increment(nonce []byte) {
	for i := range nonce {
		nonce[i]++
		if nonce[i] != 0 {
			return
		}
	}
}

// evpBytesToKey is OpenSSL's EVP_BytesToKey with MD5 and one iteration: the
// password becomes a key by hashing it with the previous digest in front. It is
// weak, it is what every Shadowsocks server implements, and a client has no
// choice in the matter.
func evpBytesToKey(password string, keyLen int) []byte {
	key := make([]byte, 0, keyLen)
	var prev []byte
	for len(key) < keyLen {
		h := md5.New()
		h.Write(prev)
		h.Write([]byte(password))
		prev = h.Sum(nil)
		key = append(key, prev...)
	}
	return key[:keyLen]
}
