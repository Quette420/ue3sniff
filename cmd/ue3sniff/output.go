package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"time"

	"github.com/quette/ue3sniff/profile"
)

// Event is one decoded field (or undecodable bunch) printed to stdout.
type Event struct {
	Time      time.Time `json:"time"`
	Direction string    `json:"dir"`
	Packet    uint32    `json:"packet"`
	Bunch     int       `json:"bunch"`

	Channel     uint16 `json:"channel"`
	ChannelType string `json:"channel_type,omitempty"`
	Sequence    uint16 `json:"seq,omitempty"`
	Reliable    bool   `json:"reliable"`
	Open        bool   `json:"open,omitempty"`
	Close       bool   `json:"close,omitempty"`
	BunchBits   int    `json:"bunch_bits"`

	Field *profile.DecodedField `json:"field,omitempty"`

	// FieldRaw is the field payload after the index, hex encoded.
	FieldRaw string `json:"field_raw,omitempty"`

	// BunchRaw is the whole bunch payload, hex encoded.
	BunchRaw string `json:"bunch_raw"`

	Error string `json:"error,omitempty"`
}

type Printer interface {
	Print(event Event)
}

func NewPrinter(format string, out io.Writer) (Printer, error) {
	switch format {
	case "text":
		return textPrinter{out: out}, nil

	case "json":
		return jsonPrinter{encoder: json.NewEncoder(out)}, nil
	}

	return nil, fmt.Errorf("unknown output format %q (text, json)", format)
}

type jsonPrinter struct {
	encoder *json.Encoder
}

func (p jsonPrinter) Print(event Event) {
	_ = p.encoder.Encode(event)
}

type textPrinter struct {
	out io.Writer
}

func (p textPrinter) Print(event Event) {
	var b strings.Builder

	fmt.Fprintf(
		&b,
		"%s %-3s pkt=%d ch=%d",
		event.Time.Format("15:04:05.000"),
		event.Direction,
		event.Packet,
		event.Channel,
	)

	if event.ChannelType != "" {
		fmt.Fprintf(&b, "(%s)", event.ChannelType)
	}

	if event.Reliable {
		fmt.Fprintf(&b, " seq=%d", event.Sequence)
	}

	if event.Open {
		b.WriteString(" open")
	}

	if event.Close {
		b.WriteString(" close")
	}

	if field := event.Field; field != nil {
		status := ""

		switch {
		case !field.Known:
			status = " UNKNOWN"
		case field.Opaque:
			status = " opaque"
		}

		params := ""
		if len(field.Params) > 0 {
			params = " (" + profile.FormatValues(field.Params) + ")"
		}

		fmt.Fprintf(
			&b,
			" %s.%s#%d%s%s bits=%d..%d/%d",
			field.Class,
			field.DisplayName(),
			field.Index,
			status,
			params,
			field.BeginBit,
			field.EndBit,
			event.BunchBits,
		)

		if event.FieldRaw != "" {
			fmt.Fprintf(&b, " payload=%s", event.FieldRaw)
		}
	} else {
		fmt.Fprintf(&b, " bits=%d raw=%s", event.BunchBits, event.BunchRaw)
	}

	if event.Error != "" {
		fmt.Fprintf(&b, " error=%q", event.Error)
	}

	b.WriteByte('\n')

	_, _ = io.WriteString(p.out, b.String())
}

func hexOrEmpty(data []byte) string {
	if len(data) == 0 {
		return ""
	}

	return hex.EncodeToString(data)
}
