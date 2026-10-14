package profile

import (
	"testing"

	"github.com/quette/ue3sniff/ue3"
)

func loadAPB(t *testing.T) *Class {
	t.Helper()

	p, err := Load("apb")
	if err != nil {
		t.Fatalf("Load(apb): %v", err)
	}

	class := p.ClassForChannel(2)
	if class == nil || class.Name != "PlayerController" {
		t.Fatalf("channel 2 class = %v, want PlayerController", class)
	}

	return class
}

func TestBuiltinProfilesParse(t *testing.T) {
	for _, name := range Builtin() {
		if _, err := Load(name); err != nil {
			t.Errorf("Load(%s): %v", name, err)
		}
	}
}

func TestDecodeCSAKeyReleasedFixture(t *testing.T) {
	class := loadAPB(t)

	fields, err := class.DecodeBunch(ue3.Bunch{
		Kind:         ue3.BunchData,
		DataBitCount: 42,
		RawData:      []byte{0x59, 0x0B, 0x00, 0x00, 0x00, 0x00},
	})
	if err != nil {
		t.Fatalf("DecodeBunch: %v", err)
	}

	if len(fields) != 1 {
		t.Fatalf("got %d fields, want 1", len(fields))
	}

	field := fields[0]

	if field.Index != 345 || field.Name != "ServerCSAKeyReleased" {
		t.Fatalf("field = %d %q, want 345 ServerCSAKeyReleased", field.Index, field.Name)
	}

	if field.IndexBits != 9 {
		t.Fatalf("IndexBits = %d, want 9", field.IndexBits)
	}

	mapping := field.Params[0]
	if !mapping.Present || mapping.Value != int32(2) {
		t.Fatalf("InputMapping = %v present=%v, want 2", mapping.Value, mapping.Present)
	}

	if field.EndBit != 42 {
		t.Fatalf("EndBit = %d, want 42", field.EndBit)
	}
}

func TestDecodeOpaqueFieldStops(t *testing.T) {
	class := loadAPB(t)

	fields, err := class.DecodeBunch(ue3.Bunch{
		Kind:         ue3.BunchData,
		DataBitCount: 9,
		RawData:      []byte{0xAB, 0x01},
	})
	if err != nil {
		t.Fatalf("DecodeBunch: %v", err)
	}

	if len(fields) != 1 ||
		fields[0].Index != 427 ||
		fields[0].Name != "ServerCompleteSuccessfulyAutoMoveToCSA" ||
		!fields[0].Opaque ||
		fields[0].EndBit != 9 {
		t.Fatalf("unexpected fields: %+v", fields)
	}
}

func TestDecodeUnknownFieldReportsError(t *testing.T) {
	class := loadAPB(t)

	// Index 1 is not in the APB table.
	_, err := class.DecodeBunch(ue3.Bunch{
		Kind:         ue3.BunchData,
		DataBitCount: 16,
		RawData:      []byte{0x01, 0x00},
	})
	if err == nil {
		t.Fatal("expected unknown field error")
	}
}

func TestSelector(t *testing.T) {
	p, err := Load("apb")
	if err != nil {
		t.Fatal(err)
	}

	s, err := p.NewSelector("csa, ServerSelectSpawnZone, 78")
	if err != nil {
		t.Fatal(err)
	}

	cases := []struct {
		index uint32
		name  string
		want  bool
	}{
		{343, "ServerCSAKeyPressed", true},
		{427, "ServerCompleteSuccessfulyAutoMoveToCSA", true},
		{371, "ServerSelectSpawnZone", true},
		{78, "KnownField78", true},
		{90, "ServerUpdateLevelVisibility", false},
	}

	for _, c := range cases {
		if got := s.Match("PlayerController", c.index, c.name); got != c.want {
			t.Errorf("Match(%d %s) = %v, want %v", c.index, c.name, got, c.want)
		}
	}
}

type bitWriter struct {
	data []byte
	pos  int
}

func (w *bitWriter) bits(value uint32, count int) {
	for i := 0; i < count; i++ {
		if w.pos/8 >= len(w.data) {
			w.data = append(w.data, 0)
		}

		if value&(1<<i) != 0 {
			w.data[w.pos/8] |= 1 << (w.pos % 8)
		}

		w.pos++
	}
}

func (w *bitWriter) bit(value bool) {
	if value {
		w.bits(1, 1)
	} else {
		w.bits(0, 1)
	}
}

// bounded mirrors ue3.BitReader.ReadBoundedInt.
func (w *bitWriter) bounded(value, max uint32) {
	var acc uint32

	for mask := uint32(1); acc+mask < max; mask <<= 1 {
		set := value&mask != 0
		w.bit(set)

		if set {
			acc |= mask
		}

		if mask == 0x80000000 {
			break
		}
	}
}

func TestDecodeCSAKeyPressedWithTarget(t *testing.T) {
	class := loadAPB(t)

	var w bitWriter

	w.bounded(343, 634)
	w.bit(true) // InputMapping present
	w.bits(5, 32)
	w.bit(false) // AimRotation default
	w.bit(true)  // CameraCollidePercent present
	w.bits(0x3F000000, 32)
	w.bit(true) // Target present
	w.bit(true) // by channel
	w.bounded(17, 0x3FF)

	fields, err := class.DecodeBunch(ue3.Bunch{
		Kind:         ue3.BunchData,
		DataBitCount: uint16(w.pos),
		RawData:      w.data,
	})
	if err != nil {
		t.Fatalf("DecodeBunch: %v", err)
	}

	got := FormatValues(fields[0].Params)
	want := "InputMapping=5, AimRotation=<default>, CameraCollidePercent=0.5, Target=channel:17"

	if got != want {
		t.Fatalf("params = %s\nwant      %s", got, want)
	}

	if fields[0].EndBit != w.pos {
		t.Fatalf("EndBit = %d, want %d", fields[0].EndBit, w.pos)
	}
}
