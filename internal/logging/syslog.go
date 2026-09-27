package logging

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"log/syslog"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"
)

// SyslogHandler is an slog.Handler that writes to the local syslog daemon.
// Levels map to syslog priorities so receiving tools can filter both ways:
//
//	slog.LevelError -> LOG_ERR
//	slog.LevelWarn  -> LOG_WARNING
//	slog.LevelInfo  -> LOG_NOTICE
//	LevelVerbose    -> LOG_INFO
//	slog.LevelDebug -> LOG_DEBUG
//
// Records are formatted as "msg key=value key=value ..." (one line per record).
// On a write error, falls back to the configured fallback writer (typically
// stderr) so logs are never silently dropped.
type SyslogHandler struct {
	mu       *sync.Mutex
	w        *syslog.Writer
	fallback io.Writer
	level    slog.Leveler
	attrs    []slog.Attr
	groups   []string
}

// NewSyslogHandler opens a connection to the local syslog daemon with the
// LOG_MAIL facility and the given tag. fallback receives any line that fails
// to write to syslog; pass os.Stderr in production.
func NewSyslogHandler(tag string, level slog.Leveler, fallback io.Writer) (*SyslogHandler, error) {
	// Severity here is just an initial value; per-record dispatch picks the
	// real severity. Facility (LOG_MAIL) is fixed for the connection.
	w, err := syslog.New(syslog.LOG_MAIL|syslog.LOG_INFO, tag)
	if err != nil {
		return nil, fmt.Errorf("open syslog: %w", err)
	}
	return &SyslogHandler{
		mu:       &sync.Mutex{},
		w:        w,
		fallback: fallback,
		level:    level,
	}, nil
}

func (h *SyslogHandler) Enabled(_ context.Context, lvl slog.Level) bool {
	return lvl >= h.level.Level()
}

func (h *SyslogHandler) Handle(_ context.Context, r slog.Record) error {
	var b strings.Builder
	b.Grow(64 + len(r.Message))
	b.WriteString(r.Message)

	// Pre-bound attrs (from WithAttrs).
	for _, a := range h.attrs {
		writeAttr(&b, a)
	}
	// Per-record attrs.
	r.Attrs(func(a slog.Attr) bool {
		writeAttr(&b, a)
		return true
	})

	msg := b.String()

	h.mu.Lock()
	defer h.mu.Unlock()

	var err error
	switch {
	case r.Level >= slog.LevelError:
		err = h.w.Err(msg)
	case r.Level >= slog.LevelWarn:
		err = h.w.Warning(msg)
	case r.Level >= slog.LevelInfo:
		err = h.w.Notice(msg)
	case r.Level >= LevelVerbose:
		err = h.w.Info(msg)
	default:
		err = h.w.Debug(msg)
	}

	if err != nil && h.fallback != nil {
		// Fallback path: tag the line so operators see why syslog failed.
		ts := r.Time.Format(time.RFC3339)
		fmt.Fprintf(h.fallback, "%s [%s] (syslog error: %v) %s\n", ts, LevelString(r.Level), err, msg)
	}
	return nil
}

func (h *SyslogHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	n := *h
	n.attrs = append(slices.Clone(h.attrs), attrs...)
	return &n
}

func (h *SyslogHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	n := *h
	n.groups = append(slices.Clone(h.groups), name)
	return &n
}

// Close releases the syslog connection. Safe to call multiple times.
func (h *SyslogHandler) Close() error {
	if h.w == nil {
		return nil
	}
	return h.w.Close()
}

// writeAttr appends " key=value" to b, quoting values that contain spaces or
// equals signs to keep the line parseable.
func writeAttr(b *strings.Builder, a slog.Attr) {
	if a.Equal(slog.Attr{}) {
		return
	}
	b.WriteByte(' ')
	b.WriteString(a.Key)
	b.WriteByte('=')
	formatValue(b, a.Value)
}

func formatValue(b *strings.Builder, v slog.Value) {
	switch v.Kind() {
	case slog.KindString:
		s := v.String()
		if needsQuoting(s) {
			b.WriteString(strconv.Quote(s))
		} else {
			b.WriteString(s)
		}
	case slog.KindInt64:
		b.WriteString(strconv.FormatInt(v.Int64(), 10))
	case slog.KindUint64:
		b.WriteString(strconv.FormatUint(v.Uint64(), 10))
	case slog.KindFloat64:
		b.WriteString(strconv.FormatFloat(v.Float64(), 'g', -1, 64))
	case slog.KindBool:
		b.WriteString(strconv.FormatBool(v.Bool()))
	case slog.KindDuration:
		b.WriteString(v.Duration().String())
	case slog.KindTime:
		b.WriteString(v.Time().Format(time.RFC3339))
	case slog.KindGroup:
		// Flatten group as key.subkey=val.
		b.WriteByte('{')
		for i, ga := range v.Group() {
			if i > 0 {
				b.WriteByte(' ')
			}
			b.WriteString(ga.Key)
			b.WriteByte('=')
			formatValue(b, ga.Value)
		}
		b.WriteByte('}')
	default:
		fmt.Fprintf(b, "%v", v.Any())
	}
}

func needsQuoting(s string) bool {
	if s == "" {
		return true
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c == ' ' || c == '=' || c == '"' || c < 0x20 {
			return true
		}
	}
	return false
}
