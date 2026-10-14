// Package profile describes a single UE3 game: packet layout, cipher and the
// replicated field / RPC tables of the classes the user cares about.
package profile

import (
	"embed"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/quette/ue3sniff/crypto"
	"github.com/quette/ue3sniff/ue3"
)

//go:embed builtin/*.json
var builtin embed.FS

type Profile struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`

	Layout ue3.Layout    `json:"layout"`
	Cipher crypto.Config `json:"cipher"`

	// ChannelTypes names the numeric channel types (1 = Control, ...).
	ChannelTypes map[string]string `json:"channel_types,omitempty"`

	// Channels statically binds a channel index to a class name, e.g. the
	// player controller channel.
	Channels map[string]string `json:"channels,omitempty"`

	Classes map[string]*Class `json:"classes,omitempty"`

	// Watch groups are named field selections usable with -watch.
	Watch map[string][]string `json:"watch,omitempty"`

	channels map[uint16]*Class
}

type Class struct {
	Name string `json:"-"`

	// FieldMax is the bound used for SerializeInt of the field index
	// (number of replicated properties + RPCs of the class).
	FieldMax uint32 `json:"field_max"`

	Fields map[string]*Field `json:"fields"`

	fields map[uint32]*Field
}

type Field struct {
	Index uint32 `json:"-"`
	Name  string `json:"name"`

	// TotalBits is the full width of a fixed-size field, index included.
	TotalBits int `json:"total_bits,omitempty"`

	// Params describes RPC parameters. A nil slice means the layout is
	// unknown; an empty slice means the RPC takes no parameters.
	Params []Param `json:"params"`

	Note string `json:"note,omitempty"`
}

// KnownWidth reports whether the decoder can step over this field and keep
// parsing the bunch.
func (f *Field) KnownWidth() bool {
	return f.TotalBits > 0 || f.Params != nil
}

func Load(nameOrPath string) (*Profile, error) {
	var (
		data []byte
		err  error
	)

	if strings.ContainsAny(nameOrPath, `/\.`) {
		data, err = os.ReadFile(nameOrPath)
	} else {
		data, err = builtin.ReadFile("builtin/" + nameOrPath + ".json")
		if err != nil {
			err = fmt.Errorf(
				"unknown built-in profile %q (available: %s)",
				nameOrPath,
				strings.Join(Builtin(), ", "),
			)
		}
	}

	if err != nil {
		return nil, err
	}

	return Parse(data)
}

// Builtin lists the names of the embedded profiles.
func Builtin() []string {
	entries, _ := builtin.ReadDir("builtin")

	names := make([]string, 0, len(entries))

	for _, entry := range entries {
		names = append(names, strings.TrimSuffix(entry.Name(), filepath.Ext(entry.Name())))
	}

	sort.Strings(names)

	return names
}

func Parse(data []byte) (*Profile, error) {
	p := &Profile{
		Layout: ue3.DefaultLayout,
	}

	if err := json.Unmarshal(data, p); err != nil {
		return nil, fmt.Errorf("parse profile: %w", err)
	}

	if err := p.index(); err != nil {
		return nil, fmt.Errorf("profile %q: %w", p.Name, err)
	}

	return p, nil
}

func (p *Profile) index() error {
	for name, class := range p.Classes {
		class.Name = name
		class.fields = make(map[uint32]*Field, len(class.Fields))

		for key, field := range class.Fields {
			index, err := strconv.ParseUint(key, 10, 32)
			if err != nil {
				return fmt.Errorf("class %s: bad field index %q", name, key)
			}

			if class.FieldMax != 0 && uint32(index) >= class.FieldMax {
				return fmt.Errorf(
					"class %s: field %d >= field_max %d",
					name,
					index,
					class.FieldMax,
				)
			}

			field.Index = uint32(index)

			if field.Name == "" {
				field.Name = "Field" + key
			}

			for _, param := range field.Params {
				if err := param.validate(); err != nil {
					return fmt.Errorf("%s.%s: %w", name, field.Name, err)
				}
			}

			class.fields[field.Index] = field
		}
	}

	p.channels = make(map[uint16]*Class, len(p.Channels))

	for key, className := range p.Channels {
		index, err := strconv.ParseUint(key, 10, 16)
		if err != nil {
			return fmt.Errorf("bad channel index %q", key)
		}

		class, ok := p.Classes[className]
		if !ok {
			return fmt.Errorf("channel %d: unknown class %q", index, className)
		}

		p.channels[uint16(index)] = class
	}

	return nil
}

// ClassForChannel returns the class bound to a channel index, if any.
func (p *Profile) ClassForChannel(channel uint16) *Class {
	return p.channels[channel]
}

func (p *Profile) ChannelTypeName(channelType uint8) string {
	if name, ok := p.ChannelTypes[strconv.Itoa(int(channelType))]; ok {
		return name
	}

	return strconv.Itoa(int(channelType))
}

func (c *Class) Field(index uint32) (*Field, bool) {
	field, ok := c.fields[index]
	return field, ok
}

// Selector matches decoded fields for -watch.
type Selector struct {
	names  map[string]bool
	ranges [][2]uint32
}

// NewSelector parses a comma separated list of watch group names, field
// names (optionally Class.Field), indices and ranges such as 338-345.
func (p *Profile) NewSelector(spec string) (*Selector, error) {
	s := &Selector{names: make(map[string]bool)}

	var add func(token string, depth int) error

	add = func(token string, depth int) error {
		token = strings.TrimSpace(token)

		if token == "" {
			return nil
		}

		if group, ok := p.Watch[token]; ok && depth == 0 {
			for _, item := range group {
				if err := add(item, depth+1); err != nil {
					return err
				}
			}

			return nil
		}

		if low, high, found := strings.Cut(token, "-"); found {
			lo, err1 := strconv.ParseUint(low, 10, 32)
			hi, err2 := strconv.ParseUint(high, 10, 32)

			if err1 != nil || err2 != nil || lo > hi {
				return fmt.Errorf("bad watch range %q", token)
			}

			s.ranges = append(s.ranges, [2]uint32{uint32(lo), uint32(hi)})

			return nil
		}

		if index, err := strconv.ParseUint(token, 10, 32); err == nil {
			s.ranges = append(s.ranges, [2]uint32{uint32(index), uint32(index)})
			return nil
		}

		s.names[token] = true

		return nil
	}

	for _, token := range strings.Split(spec, ",") {
		if err := add(token, 0); err != nil {
			return nil, err
		}
	}

	return s, nil
}

func (s *Selector) Match(className string, index uint32, name string) bool {
	if s.names[name] || s.names[className+"."+name] {
		return true
	}

	for _, r := range s.ranges {
		if index >= r[0] && index <= r[1] {
			return true
		}
	}

	return false
}
