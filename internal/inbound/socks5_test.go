package inbound

import (
	"context"
	"encoding/binary"
	"io"
	"net"
	"testing"
	"time"

	"github.com/aqiyoung/skyward-kernel/internal/logx"
)

// echoServer answers every byte it reads, which is enough to prove a relay
// works end to end.
func echoServer(t *testing.T) net.Listener {
	t.Helper()
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("echo listen: %v", err)
	}
	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func() {
				defer conn.Close()
				io.Copy(conn, conn)
			}()
		}
	}()
	return listener
}

func startSocks(t *testing.T, dial Dialer) *Socks5 {
	t.Helper()
	server := &Socks5{
		Listen: "127.0.0.1:0",
		Dial:   dial,
		Log:    logx.New(logx.LevelError, io.Discard),
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go server.Serve(ctx)

	deadline := time.Now().Add(2 * time.Second)
	for server.Addr() == "" && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if server.Addr() == "" {
		t.Fatal("socks listener never bound")
	}
	return server
}

func TestSocks5Connect(t *testing.T) {
	echo := echoServer(t)
	defer echo.Close()
	echoAddr := echo.Addr().(*net.TCPAddr)

	server := startSocks(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return net.Dial(network, addr)
	})

	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	// Greeting: version 5, one method, no authentication.
	if _, err := conn.Write([]byte{0x05, 0x01, 0x00}); err != nil {
		t.Fatalf("greeting: %v", err)
	}
	reply := make([]byte, 2)
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("greeting reply: %v", err)
	}
	if reply[0] != 0x05 || reply[1] != 0x00 {
		t.Fatalf("greeting reply = %v", reply)
	}

	// Request: CONNECT to the echo server.
	ip4 := echoAddr.IP.To4()
	if ip4 == nil {
		t.Fatalf("echo server is not on IPv4: %v", echoAddr.IP)
	}
	request := []byte{0x05, 0x01, 0x00, 0x01, ip4[0], ip4[1], ip4[2], ip4[3], 0, 0}
	binary.BigEndian.PutUint16(request[8:10], uint16(echoAddr.Port))
	if _, err := conn.Write(request); err != nil {
		t.Fatalf("request: %v", err)
	}
	head := make([]byte, 10)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("request reply: %v", err)
	}
	if head[1] != replySucceeded {
		t.Fatalf("request reply code = %d", head[1])
	}

	if _, err := conn.Write([]byte("ping")); err != nil {
		t.Fatalf("write: %v", err)
	}
	got := make([]byte, 4)
	if _, err := io.ReadFull(conn, got); err != nil {
		t.Fatalf("read echo: %v", err)
	}
	if string(got) != "ping" {
		t.Fatalf("echo = %q", got)
	}
}

func TestSocks5RefusesBind(t *testing.T) {
	server := startSocks(t, func(ctx context.Context, network, addr string) (net.Conn, error) {
		return nil, io.EOF
	})
	conn, err := net.Dial("tcp", server.Addr())
	if err != nil {
		t.Fatalf("dial socks: %v", err)
	}
	defer conn.Close()
	conn.SetDeadline(time.Now().Add(5 * time.Second))

	conn.Write([]byte{0x05, 0x01, 0x00})
	reply := make([]byte, 2)
	io.ReadFull(conn, reply)

	// BIND (0x02) is not implemented; the client must be told, not left hanging.
	conn.Write([]byte{0x05, 0x02, 0x00, 0x01, 1, 2, 3, 4, 0, 80})
	head := make([]byte, 10)
	if _, err := io.ReadFull(conn, head); err != nil {
		t.Fatalf("reply: %v", err)
	}
	if head[1] != replyCommandRefused {
		t.Fatalf("reply code = %d, want %d", head[1], replyCommandRefused)
	}
}
