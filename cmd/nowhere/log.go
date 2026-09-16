package main

import (
	"context"
	"fmt"
	"os"
	"sync"

	"github.com/ohmycggk/nowhere-go/diagnostic"
)

type logger struct {
	mu    sync.Mutex
	level logLevel
}

func newLogger(level logLevel) *logger { return &logger{level: level} }

func (l *logger) enabled(level logLevel) bool {
	return l != nil && l.level != logNone && (l.level == logEvent || level <= l.level)
}

func (l *logger) printf(level logLevel, format string, args ...any) {
	if !l.enabled(level) {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	fmt.Fprintf(os.Stderr, format+"\n", args...)
}

func (l *logger) info(format string, args ...any)  { l.printf(logInfo, format, args...) }
func (l *logger) warn(format string, args ...any)  { l.printf(logWarn, format, args...) }
func (l *logger) error(format string, args ...any) { l.printf(logError, format, args...) }
func (l *logger) debug(format string, args ...any) { l.printf(logDebug, format, args...) }

func (l *logger) Observe(_ context.Context, event diagnostic.Event) {
	level := logInfo
	switch event.Level {
	case diagnostic.LevelDebug:
		level = logDebug
	case diagnostic.LevelWarn:
		level = logWarn
	case diagnostic.LevelError:
		level = logError
	}
	l.printf(level, "%s", diagnostic.FormatEvent(event))
}

var _ diagnostic.Observer = (*logger)(nil)
