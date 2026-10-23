// Package logx is the kernel's logger: levelled, timestamped, and small enough
// to read in one sitting. The kernel is a library first, so nothing here writes
// to a file of its own; the caller decides where stderr goes.
package logx

import (
	"fmt"
	"io"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

// Level is how much the logger keeps. The order is the one users expect: a
// higher level keeps more.
type Level int32

const (
	LevelError Level = iota
	LevelWarn
	LevelInfo
	LevelDebug
)

// String is the name the config file uses.
func (l Level) String() string {
	switch l {
	case LevelError:
		return "error"
	case LevelWarn:
		return "warn"
	case LevelDebug:
		return "debug"
	default:
		return "info"
	}
}

// ParseLevel accepts the names the config uses, and says which ones exist.
func ParseLevel(s string) (Level, error) {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "", "info":
		return LevelInfo, nil
	case "error":
		return LevelError, nil
	case "warn", "warning":
		return LevelWarn, nil
	case "debug", "trace":
		return LevelDebug, nil
	}
	return LevelInfo, fmt.Errorf("unknown log level %q (want error, warn, info or debug)", s)
}

// Logger writes one line per call, with the level and a timestamp.
type Logger struct {
	mu    sync.Mutex
	out   io.Writer
	level atomic.Int32
}

// New builds a logger at the given level. A nil writer means stderr.
func New(level Level, out io.Writer) *Logger {
	if out == nil {
		out = os.Stderr
	}
	l := &Logger{out: out}
	l.level.Store(int32(level))
	return l
}

// SetLevel changes the level while running.
func (l *Logger) SetLevel(level Level) { l.level.Store(int32(level)) }

// Enabled reports whether a level would be written. Callers use it to skip
// building expensive arguments.
func (l *Logger) Enabled(level Level) bool { return level <= Level(l.level.Load()) }

func (l *Logger) write(level Level, format string, args ...any) {
	if l == nil || !l.Enabled(level) {
		return
	}
	line := fmt.Sprintf(format, args...)
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(l.out, "%s %-5s %s\n", time.Now().Format("2006-01-02 15:04:05.000"), strings.ToUpper(level.String()), line)
}

func (l *Logger) Errorf(format string, args ...any) { l.write(LevelError, format, args...) }
func (l *Logger) Warnf(format string, args ...any)  { l.write(LevelWarn, format, args...) }
func (l *Logger) Infof(format string, args ...any)  { l.write(LevelInfo, format, args...) }
func (l *Logger) Debugf(format string, args ...any) { l.write(LevelDebug, format, args...) }
