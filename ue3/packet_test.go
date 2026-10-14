package ue3

import "testing"

// apbLayout mirrors profiles/apb.json.
var apbLayout = Layout{
	PacketIDBits:     16,
	HeaderSkipBits:   14,
	AckHasIDFlag:     true,
	AckIDBits:        30,
	ChannelIndexBits: 10,
	SequenceBits:     10,
	ChannelTypeBits:  3,
	BunchSizeBits:    12,
}

func TestParseAPBEMUFixture(t *testing.T) {
	data := []byte{
		0x00, 0x00, 0x00, 0x80, 0x05, 0x20, 0x80, 0x60,
		0xC9, 0x11, 0x00, 0x00, 0x40, 0x50, 0x15, 0x15,
		0x12, 0x48, 0xD0, 0xD0, 0x50, 0x12, 0x51, 0x0F,
		0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C, 0x0C,
		0x4C, 0x0C, 0x48, 0x50, 0x15, 0x15, 0xD2, 0x52,
		0x51, 0x56, 0x4F, 0x8E, 0x91, 0x0D, 0x0C, 0x4D,
		0x8D, 0x91, 0x0D, 0x4E, 0x4D, 0xCD, 0x0C, 0x4E,
		0x4D, 0x4C, 0x91, 0x10, 0xD1, 0xCC, 0x4D, 0x4E,
		0x8E, 0x4C, 0xCD, 0x0C, 0xCC, 0x4D, 0x8E, 0x10,
		0x4E, 0x91, 0x8C, 0x8D, 0x4D, 0x11, 0xCE, 0x90,
		0x10, 0x0E, 0x11, 0x40,
	}

	packet, err := ParsePacket(data, apbLayout)
	if err != nil {
		t.Fatalf("ParsePacket failed: %v", err)
	}

	if packet.PacketID != 0 {
		t.Fatalf("PacketID = %d, want 0", packet.PacketID)
	}

	if len(packet.Bunches) != 1 {
		t.Fatalf(
			"Bunch count = %d, want 1",
			len(packet.Bunches),
		)
	}

	bunch := packet.Bunches[0]

	if bunch.Kind != BunchData {
		t.Fatalf("Bunch kind = %v, want DATA", bunch.Kind)
	}

	if !bunch.Open {
		t.Fatal("Open = false, want true")
	}

	if !bunch.Reliable {
		t.Fatal("Reliable = false, want true")
	}

	if bunch.ChannelIndex != 0 {
		t.Fatalf(
			"ChannelIndex = %d, want 0",
			bunch.ChannelIndex,
		)
	}

	if bunch.ChannelSequence != 1 {
		t.Fatalf(
			"ChannelSequence = %d, want 1",
			bunch.ChannelSequence,
		)
	}

	if bunch.ChannelType != 1 {
		t.Fatalf(
			"ChannelType = %d, want 1",
			bunch.ChannelType,
		)
	}

	if bunch.DataBitCount != 600 {
		t.Fatalf(
			"DataBitCount = %d, want 600",
			bunch.DataBitCount,
		)
	}
}
