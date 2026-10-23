// Package inbound is how traffic reaches the kernel. v0.1 speaks SOCKS5 without
// authentication, which is what a desktop makes of "system proxy" and what the
// app can point a test client at.
package inbound

import (
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"strconv"
	"sync"
	"time"

	"github.com/aqiyoung/skyward-kernel/internal/logx"
)

// Dialer is what an inbound calls once it knows where the stream should go.
type Dialer func(ctx context.Context, network, addr string) (net.Conn, error)

// Socks5 is a SOCKS5 listener.
type Socks5 struct {
	Listen string
	Dial   Dialer
	Log    *logx.Logger

	// mu guards ln: Serve binds it while a caller may already be asking where the
	// listener landed, which is what a test does with port 0.
	mu sync.Mutex
	ln net.Listener
}

// Addr is the address actually bound, which is useful when Listen asked for
// port 0. It is empty until Serve has bound.
func (s *Socks5) Addr() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.ln == nil {
		return ""
	}
	return s.ln.Addr().String()
}

func (s *Socks5) listener() net.Listener {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.ln
}

// Serve binds and accepts until the context is cancelled.
func (s *Socks5) Serve(ctx context.Context) error {
	ln, err := net.Listen("tcp", s.Listen)
	if err != nil {
		return fmt.Errorf("listen on %s: %w", s.Listen, err)
	}
	s.mu.Lock()
	s.ln = ln
	s.mu.Unlock()
	s.Log.Infof("socks5 listening on %s", ln.Addr())

	go func() {
		<-ctx.Done()
		ln.Close()
	}()

	for {
		conn, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return nil
			}
			return err
		}
		go s.handle(ctx, conn)
	}
}

// Close stops the listener.
func (s *Socks5) Close() error {
	ln := s.listener()
	if ln == nil {
		return nil
	}
	return ln.Close()
}

func (s *Socks5) handle(ctx context.Context, client net.Conn) {
	defer client.Close()

	// A handshake that never finishes would hold a goroutine per stalled client.
	client.SetDeadline(time.Now().Add(30 * time.Second))

	addr, err := handshake(client)
	if err != nil {
		s.Log.Debugf("socks5 %s: %v", client.RemoteAddr(), err)
		return
	}
	client.SetDeadline(time.Time{})

	remote, err := s.Dial(ctx, "tcp", addr)
	if err != nil {
		writeReply(client, replyHostUnreachable)
		s.Log.Debugf("socks5 %s -> %s: %v", client.RemoteAddr(), addr, err)
		return
	}
	defer remote.Close()

	if err := writeReply(client, replySucceeded); err != nil {
		return
	}
	if s.Log.Enabled(logx.LevelDebug) {
		s.Log.Debugf("socks5 %s -> %s via %s", client.RemoteAddr(), addr, remote.RemoteAddr())
	}
	relay(client, remote)
}

const (
	socks5Version = 0x05

	replySucceeded       = 0x00
	replyHostUnreachable = 0x04
	replyCommandRefused  = 0x07
)

// handshake runs the greeting and the request, and returns the destination.
func handshake(conn net.Conn) (string, error) {
	header := make([]byte, 2)
	if _, err := io.ReadFull(conn, header); err != nil {
		return "", err
	}
	if header[0] != socks5Version {
		return "", fmt.Errorf("not socks5 (version %d)", header[0])
	}
	methods := make([]byte, int(header[1]))
	if _, err := io.ReadFull(conn, methods); err != nil {
		return "", err
	}
	// No authentication: the listener is bound to loopback by configuration.
	if _, err := conn.Write([]byte{socks5Version, 0x00}); err != nil {
		return "", err
	}

	request := make([]byte, 4)
	if _, err := io.ReadFull(conn, request); err != nil {
		return "", err
	}
	if request[0] != socks5Version {
		return "", fmt.Errorf("request from a client speaking version %d", request[0])
	}
	if request[1] != 0x01 {
		// UDP ASSOCIATE and BIND are not part of v0.1; saying so is better than a
		// silently dead stream.
		writeReply(conn, replyCommandRefused)
		return "", fmt.Errorf("command %d is not implemented", request[1])
	}

	host, err := readAddress(conn, request[3])
	if err != nil {
		return "", err
	}
	portBytes := make([]byte, 2)
	if _, err := io.ReadFull(conn, portBytes); err != nil {
		return "", err
	}
	return net.JoinHostPort(host, strconv.Itoa(int(binary.BigEndian.Uint16(portBytes)))), nil
}

func readAddress(conn net.Conn, atyp byte) (string, error) {
	switch atyp {
	case 0x01: // IPv4
		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	case 0x03: // domain
		length := make([]byte, 1)
		if _, err := io.ReadFull(conn, length); err != nil {
			return "", err
		}
		buf := make([]byte, int(length[0]))
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return string(buf), nil
	case 0x04: // IPv6
		buf := make([]byte, 16)
		if _, err := io.ReadFull(conn, buf); err != nil {
			return "", err
		}
		return net.IP(buf).String(), nil
	}
	return "", fmt.Errorf("address type %d is not defined", atyp)
}

func writeReply(conn net.Conn, code byte) error {
	// BND.ADDR/BND.PORT are meaningless to a client that only asked for a stream,
	// and every client in the wild ignores them.
	_, err := conn.Write([]byte{socks5Version, code, 0x00, 0x01, 0, 0, 0, 0, 0, 0})
	return err
}

// relay copies both ways and closes each direction as its source ends, so a half
// closed stream still delivers what was already sent.
func relay(a, b net.Conn) {
	var wg sync.WaitGroup
	wg.Add(2)
	go func() {
		defer wg.Done()
		io.Copy(a, b)
		closeWrite(a)
	}()
	go func() {
		defer wg.Done()
		io.Copy(b, a)
		closeWrite(b)
	}()
	wg.Wait()
}

func closeWrite(conn net.Conn) {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		if err := cw.CloseWrite(); err != nil && !errors.Is(err, net.ErrClosed) {
			conn.Close()
		}
		return
	}
	conn.Close()
}
