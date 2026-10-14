package profile

import (
	"fmt"
	"math"
	"strings"
	"unicode/utf16"

	"github.com/quette/ue3sniff/ue3"
)

// Param is one RPC parameter.
//
// UE3 serializes every non-bool RPC parameter behind a one-bit "non-default"
// flag; a cleared flag means the parameter has its default value and no
// payload follows. Bool parameters are just the bit itself.
type Param struct {
	Name string `json:"name"`

	// Type: bool, byte, int, uint, float, enum, bits, object, string,
	// rotator.
	Type string `json:"type"`

	// Bits is the width for "bits".
	Bits int `json:"bits,omitempty"`

	// Max is the SerializeInt bound for "enum".
	Max uint32 `json:"max,omitempty"`

	// NoPresenceBit disables the leading non-default flag (for games
	// that serialize a parameter unconditionally).
	NoPresenceBit bool `json:"no_presence_bit,omitempty"`
}

func (p Param) validate() error {
	switch p.Type {
	case "bool", "byte", "int", "uint", "float", "object", "string", "rotator":
		return nil

	case "bits":
		if p.Bits <= 0 || p.Bits > 32 {
			return fmt.Errorf("param %s: bits must be 1..32", p.Name)
		}

		return nil

	case "enum":
		if p.Max < 2 {
			return fmt.Errorf("param %s: enum needs max >= 2", p.Name)
		}

		return nil

	default:
		return fmt.Errorf("param %s: unknown type %q", p.Name, p.Type)
	}
}

// ObjectRef is a serialized object reference: either an actor channel index
// or a package-map NetIndex.
type ObjectRef struct {
	ByChannel bool   `json:"by_channel"`
	Index     uint32 `json:"index"`
}

func (o ObjectRef) String() string {
	if o.ByChannel {
		return fmt.Sprintf("channel:%d", o.Index)
	}

	return fmt.Sprintf("netindex:%d", o.Index)
}

type Rotator struct {
	Pitch int32 `json:"pitch"`
	Yaw   int32 `json:"yaw"`
	Roll  int32 `json:"roll"`
}

type Value struct {
	Name    string `json:"name"`
	Type    string `json:"type"`
	Present bool   `json:"present"`
	Value   any    `json:"value,omitempty"`
}

func (v Value) String() string {
	if !v.Present {
		return v.Name + "=<default>"
	}

	switch value := v.Value.(type) {
	case string:
		return fmt.Sprintf("%s=%q", v.Name, value)

	case Rotator:
		return fmt.Sprintf("%s=(%d,%d,%d)", v.Name, value.Pitch, value.Yaw, value.Roll)

	default:
		return fmt.Sprintf("%s=%v", v.Name, value)
	}
}

func FormatValues(values []Value) string {
	parts := make([]string, len(values))

	for i, value := range values {
		parts[i] = value.String()
	}

	return strings.Join(parts, ", ")
}

func readParams(reader *ue3.BitReader, params []Param) ([]Value, error) {
	values := make([]Value, 0, len(params))

	for _, param := range params {
		value := Value{Name: param.Name, Type: param.Type}

		// Trailing default parameters may be cut off entirely.
		if reader.Remaining() == 0 {
			values = append(values, value)
			continue
		}

		if param.Type == "bool" {
			bit, err := reader.ReadBit()
			if err != nil {
				return values, fmt.Errorf("%s: %w", param.Name, err)
			}

			value.Present = true
			value.Value = bit
			values = append(values, value)

			continue
		}

		value.Present = true

		if !param.NoPresenceBit {
			present, err := reader.ReadBit()
			if err != nil {
				return values, fmt.Errorf("%s presence: %w", param.Name, err)
			}

			value.Present = present
		}

		if value.Present {
			decoded, err := readValue(reader, param)
			if err != nil {
				return values, fmt.Errorf("%s: %w", param.Name, err)
			}

			value.Value = decoded
		}

		values = append(values, value)
	}

	return values, nil
}

func readValue(reader *ue3.BitReader, param Param) (any, error) {
	switch param.Type {
	case "byte":
		return reader.ReadBits(8)

	case "int":
		raw, err := reader.ReadBits(32)
		return int32(raw), err

	case "uint":
		return reader.ReadBits(32)

	case "float":
		raw, err := reader.ReadBits(32)
		return math.Float32frombits(raw), err

	case "bits":
		return reader.ReadBits(param.Bits)

	case "enum":
		return reader.ReadBoundedInt(param.Max)

	case "object":
		return readObject(reader)

	case "rotator":
		return readRotator(reader)

	case "string":
		return readString(reader)
	}

	return nil, fmt.Errorf("unsupported type %q", param.Type)
}

func readObject(reader *ue3.BitReader) (ObjectRef, error) {
	var ref ObjectRef

	byChannel, err := reader.ReadBit()
	if err != nil {
		return ref, err
	}

	ref.ByChannel = byChannel

	indexMax := uint32(0x80000000)
	if byChannel {
		indexMax = 0x3FF
	}

	ref.Index, err = reader.ReadBoundedInt(indexMax)

	return ref, err
}

// readRotator follows FRotator::SerializeCompressed: each component is a
// presence bit followed by the high byte of the 16-bit angle.
func readRotator(reader *ue3.BitReader) (Rotator, error) {
	var rotator Rotator

	for _, component := range []*int32{&rotator.Pitch, &rotator.Yaw, &rotator.Roll} {
		present, err := reader.ReadBit()
		if err != nil {
			return rotator, err
		}

		if !present {
			continue
		}

		raw, err := reader.ReadBits(8)
		if err != nil {
			return rotator, err
		}

		*component = int32(raw) << 8
	}

	return rotator, nil
}

// readString follows FArchive << FString: an int32 length that includes the
// terminator, negative for UTF-16.
func readString(reader *ue3.BitReader) (string, error) {
	raw, err := reader.ReadBits(32)
	if err != nil {
		return "", err
	}

	length := int32(raw)

	if length == 0 {
		return "", nil
	}

	unicode := length < 0
	if unicode {
		length = -length
	}

	charBits := 8
	if unicode {
		charBits = 16
	}

	if int64(length)*int64(charBits) > int64(reader.Remaining()) {
		return "", fmt.Errorf("string length %d exceeds bunch", length)
	}

	if !unicode {
		bytes, err := reader.ReadBytes(int(length))
		if err != nil {
			return "", err
		}

		return strings.TrimRight(string(bytes), "\x00"), nil
	}

	units := make([]uint16, length)

	for i := range units {
		unit, err := reader.ReadBits(16)
		if err != nil {
			return "", err
		}

		units[i] = uint16(unit)
	}

	return strings.TrimRight(string(utf16.Decode(units)), "\x00"), nil
}
