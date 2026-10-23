package proxy

import (
	"bufio"
	"context"
	"crypto/hkdf"
	"crypto/sha1"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aqiyoung/skyward-kernel/internal/config"
)

// TestShadowsocksRoundTrip puts a server on loopback that speaks the same AEAD
// framing this client writes, and checks that a payload survives both
// directions. It is the only test that can catch a wrong salt, a wrong nonce
// order or a wrong chunk length without a real server.
func TestShadowsocksRoundTrip(t *testing.T) {
	for _, cipherName := range []string{"aes-128-gcm", "aes-256-gcm", "chacha20-ietf-poly1305"} {
		t.Run(cipherName, func(t *testing.T) {
			const password = "correct-horse-battery-staple"
			spec, ok := ssCiphers[cipherName]
			if !ok {
				t.Fatalf("no spec for %s", cipherName)
			}
			masterKey := evpBytesToKey(password, spec.keyLen)

			listener, err := net.Listen("tcp", "127.0.0.1:0")
			if err != nil {
				t.Fatalf("listen: %v", err)
			}
			defer listener.Close()

			go func() {
				conn, err := listener.Accept()
				if err != nil {
					return
				}
				defer conn.Close()

				salt := make([]byte, spec.keyLen)
				if _, err := io.ReadFull(conn, salt); err != nil {
					return
				}
				clientKey, err := hkdf.Key(sha1.New, masterKey, salt, "ss-subkey", spec.keyLen)
				if err != nil {
					return
				}
				server := &ssConn{
					Conn:      conn,
					reader:    bufio.NewReader(conn),
					cipher:    spec,
					masterKey: masterKey,
				}
				// The answering side opens both directions itself: it reads under the
				// key the client's salt makes, and puts its own salt on the wire before
				// it writes anything back.
				if err := server.beginReadingWith(clientKey); err != nil {
					return
				}
				if err := server.beginWritingAs(masterKey); err != nil {
					return
				}
				buf := make([]byte, 4096)
				for {
					n, err := server.Read(buf)
					if n > 0 {
						if _, werr := server.Write(buf[:n]); werr != nil {
							return
						}
					}
					if err != nil {
						return
					}
				}
			}()

			p := config.Proxy{
				Name:     "ss",
				Type:     "ss",
				Server:   "127.0.0.1",
				Port:     listener.Addr().(*net.TCPAddr).Port,
				Cipher:   cipherName,
				Password: password,
			}
			dialer, err := New(p)
			if err != nil {
				t.Fatalf("build: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()
			conn, err := dialer.DialContext(ctx, "tcp", "example.com:80")
			if err != nil {
				t.Fatalf("dial: %v", err)
			}
			defer conn.Close()

			payload := []byte("hello through the framing")
			if _, err := conn.Write(payload); err != nil {
				t.Fatalf("write: %v", err)
			}

			// The echo carries the request header back too, because the server has
			// no idea which bytes were address and which were payload; the payload
			// is what has to survive.
			got := make([]byte, 0, 256)
			buf := make([]byte, 256)
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) {
				conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
				n, err := conn.Read(buf)
				got = append(got, buf[:n]...)
				if len(got) >= len(payload)+16 || err != nil {
					break
				}
			}
			if len(got) < len(payload) || string(got[len(got)-len(payload):]) != string(payload) {
				t.Fatalf("echo %q does not end with %q", got, payload)
			}
		})
	}
}

func TestShadowsocksRejectsUnknownCipher(t *testing.T) {
	_, err := New(config.Proxy{Name: "ss", Type: "ss", Server: "127.0.0.1", Port: 1, Cipher: "rc4-md5", Password: "p"})
	if err == nil {
		t.Fatal("rc4-md5 is gone for a reason; it must not build")
	}
}

func TestSocksAddressEncoding(t *testing.T) {
	cases := []struct {
		host, port string
		want       []byte
	}{
		{"1.2.3.4", "80", []byte{0x01, 1, 2, 3, 4, 0, 80}},
		{"example.com", "443", append(append([]byte{0x03, 11}, "example.com"...), 0x01, 0xbb)},
	}
	for _, c := range cases {
		got, err := socksAddress(c.host, c.port)
		if err != nil {
			t.Fatalf("%s:%s: %v", c.host, c.port, err)
		}
		if string(got) != string(c.want) {
			t.Fatalf("%s:%s = %v, want %v", c.host, c.port, got, c.want)
		}
	}
}
