package logger

import (
	"fmt"
	"io"
	"strings"
	"time"
)

type Level int

const (
	Error Level = iota
	Info
	Debug
	Trace
)

type Logger struct {
	level Level
	out   io.Writer
}

func New(level string, out io.Writer) (*Logger, error) {
	l := &Logger{out: out}

	switch strings.ToLower(level) {
	case "error":
		l.level = Error

	case "info":
		l.level = Info

	case "debug":
		l.level = Debug

	case "trace":
		l.level = Trace

	default:
		return nil, fmt.Errorf("unknown log level %q (error, info, debug, trace)", level)
	}

	return l, nil
}

func (l *Logger) Enabled(level Level) bool {
	return level <= l.level
}

func (l *Logger) Error(format string, args ...any) {
	l.log(Error, "ERROR", format, args...)
}

func (l *Logger) Info(format string, args ...any) {
	l.log(Info, "INFO", format, args...)
}

func (l *Logger) Debug(format string, args ...any) {
	l.log(Debug, "DEBUG", format, args...)
}

func (l *Logger) Trace(format string, args ...any) {
	l.log(Trace, "TRACE", format, args...)
}

func (l *Logger) log(
	level Level,
	name string,
	format string,
	args ...any,
) {
	if level > l.level {
		return
	}

	timestamp := time.Now().Format("15:04:05.000")

	fmt.Fprintf(
		l.out,
		"[%s] %-5s %s\n",
		timestamp,
		name,
		fmt.Sprintf(format, args...),
	)
}
