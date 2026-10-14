package profile

import (
	"fmt"

	"github.com/quette/ue3sniff/ue3"
)

type DecodedField struct {
	Class string `json:"class"`
	Index uint32 `json:"index"`
	Name  string `json:"name,omitempty"`

	// Known is true when the index is present in the profile.
	Known bool `json:"known"`

	// Opaque is true when the field is known but its width is not; the
	// rest of the bunch is attributed to it and decoding stops.
	Opaque bool `json:"opaque,omitempty"`

	BeginBit  int `json:"begin_bit"`
	IndexBits int `json:"index_bits"`
	EndBit    int `json:"end_bit"`

	Params []Value `json:"params,omitempty"`

	// RawBits holds the field payload (after the index) as packed bits.
	RawBits []byte `json:"-"`
}

func (f DecodedField) DisplayName() string {
	if f.Name != "" {
		return f.Name
	}

	return fmt.Sprintf("Field%d", f.Index)
}

// DecodeBunch walks the field stream of a data bunch on a channel bound to
// class. Decoding stops at the first field whose width is unknown, because
// guessing it would corrupt every following field.
func (c *Class) DecodeBunch(bunch ue3.Bunch) ([]DecodedField, error) {
	if bunch.Kind != ue3.BunchData || bunch.DataBitCount == 0 {
		return nil, nil
	}

	end := int(bunch.DataBitCount)
	reader := ue3.NewBitReader(bunch.RawData, 0, end)

	var result []DecodedField

	for reader.Remaining() > 0 {
		begin := reader.Tell()

		index, err := reader.ReadBoundedInt(c.FieldMax)
		if err != nil {
			return result, fmt.Errorf("field index at bit %d: %w", begin, err)
		}

		field := DecodedField{
			Class:     c.Name,
			Index:     index,
			BeginBit:  begin,
			IndexBits: reader.Tell() - begin,
		}

		definition, known := c.Field(index)

		if known {
			field.Known = true
			field.Name = definition.Name
		}

		switch {
		case known && definition.TotalBits > 0:
			payloadBits := definition.TotalBits - field.IndexBits

			if payloadBits < 0 || payloadBits > reader.Remaining() {
				field.EndBit = end
				result = append(result, field)

				return result, fmt.Errorf(
					"field %d: fixed width %d does not fit (index=%d remaining=%d)",
					index,
					definition.TotalBits,
					field.IndexBits,
					reader.Remaining(),
				)
			}

			field.RawBits = ue3.ExtractBits(bunch.RawData, reader.Tell(), payloadBits)
			_ = reader.Skip(payloadBits)

		case known && definition.Params != nil:
			payloadBegin := reader.Tell()

			field.Params, err = readParams(reader, definition.Params)
			field.RawBits = ue3.ExtractBits(
				bunch.RawData,
				payloadBegin,
				reader.Tell()-payloadBegin,
			)

			if err != nil {
				field.EndBit = reader.Tell()
				result = append(result, field)

				return result, fmt.Errorf("%s: %w", field.DisplayName(), err)
			}

		default:
			field.Opaque = known
			field.RawBits = ue3.ExtractBits(bunch.RawData, reader.Tell(), reader.Remaining())
			field.EndBit = end
			result = append(result, field)

			if !known {
				return result, fmt.Errorf(
					"unknown field %d at bit %d; parameter width unknown",
					index,
					begin,
				)
			}

			return result, nil
		}

		field.EndBit = reader.Tell()
		result = append(result, field)
	}

	return result, nil
}
