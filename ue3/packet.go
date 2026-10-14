package ue3

import "fmt"

type BunchKind uint8

const (
	BunchData BunchKind = iota
	BunchAck
)

func (k BunchKind) String() string {
	if k == BunchAck {
		return "ACK"
	}

	return "DATA"
}

// Layout describes the bit widths of the UE3 packet and bunch headers.
// Games built on UE3 frequently tweak these, so they come from a profile
// instead of being hard-coded.
type Layout struct {
	// PacketIDBits is the width of the packet ID at the start of the
	// packet.
	PacketIDBits int `json:"packet_id_bits"`

	// HeaderSkipBits are skipped right after the packet ID (APB carries
	// 14 extra bits there that are not part of the ID).
	HeaderSkipBits int `json:"header_skip_bits"`

	// AckHasIDFlag means an ACK bunch carries a presence bit before
	// the acknowledged packet ID.
	AckHasIDFlag bool `json:"ack_has_id_flag"`
	AckIDBits    int  `json:"ack_id_bits"`

	ChannelIndexBits int `json:"channel_index_bits"`
	SequenceBits     int `json:"sequence_bits"`
	ChannelTypeBits  int `json:"channel_type_bits"`
	BunchSizeBits    int `json:"bunch_size_bits"`
}

// DefaultLayout matches stock UE3 (MAX_PACKETID=16384, MAX_CHANNELS=1023,
// MAX_CHSEQUENCE=1024, CHTYPE_MAX=8, MaxPacket=512).
var DefaultLayout = Layout{
	PacketIDBits:     14,
	AckIDBits:        14,
	ChannelIndexBits: 10,
	SequenceBits:     10,
	ChannelTypeBits:  3,
	BunchSizeBits:    12,
}

type Bunch struct {
	Kind BunchKind

	Open     bool
	Close    bool
	Reliable bool

	ChannelIndex    uint16
	ChannelSequence uint16
	ChannelType     uint8

	// HasChannelType is false when the header did not carry the type
	// (unreliable bunch on an already open channel).
	HasChannelType bool

	DataBitCount  uint16
	DataBitOffset int

	RawData []byte

	AckPacketID uint32
}

type Packet struct {
	PacketID        uint32
	PayloadBitCount int

	Bunches []Bunch
}

func findPayloadBitCount(data []byte) (int, error) {
	if len(data) == 0 {
		return 0, fmt.Errorf("empty packet")
	}

	// UE3 uses the highest set bit in the final non-zero byte
	// as the packet trailer marker.
	for i := len(data) - 1; i >= 0; i-- {
		value := data[i]

		if value == 0 {
			continue
		}

		for bit := 7; bit >= 0; bit-- {
			if value&(1<<bit) != 0 {
				return i*8 + bit, nil
			}
		}
	}

	return 0, fmt.Errorf("missing UE3 trailer marker")
}

// ExtractBits copies bitCount bits starting at beginBit into a new
// LSB-first packed buffer.
func ExtractBits(
	data []byte,
	beginBit int,
	bitCount int,
) []byte {
	result := make([]byte, (bitCount+7)/8)

	for i := 0; i < bitCount; i++ {
		sourceBit := beginBit + i

		value := (data[sourceBit/8] >> (sourceBit % 8)) & 1

		if value != 0 {
			result[i/8] |= 1 << (i % 8)
		}
	}

	return result
}

// ParsePacket parses a decrypted UDP payload using the given layout.
func ParsePacket(data []byte, layout Layout) (Packet, error) {
	var packet Packet

	payloadBitCount, err := findPayloadBitCount(data)
	if err != nil {
		return packet, err
	}

	packet.PayloadBitCount = payloadBitCount

	reader := NewBitReader(
		data,
		0,
		payloadBitCount,
	)

	if packet.PacketID, err = reader.ReadBits(layout.PacketIDBits); err != nil {
		return packet, fmt.Errorf("truncated packet id: %w", err)
	}

	if err := reader.Skip(layout.HeaderSkipBits); err != nil {
		return packet, fmt.Errorf("truncated packet header: %w", err)
	}

	for reader.Remaining() > 0 {
		bunch, err := parseBunch(reader, layout)
		if err != nil {
			return packet, err
		}

		packet.Bunches = append(packet.Bunches, bunch)
	}

	return packet, nil
}

func parseBunch(reader *BitReader, layout Layout) (Bunch, error) {
	isAck, err := reader.ReadBit()
	if err != nil {
		return Bunch{}, fmt.Errorf("truncated ACK/data flag: %w", err)
	}

	if isAck {
		return parseAckBunch(reader, layout)
	}

	return parseDataBunch(reader, layout)
}

func parseAckBunch(reader *BitReader, layout Layout) (Bunch, error) {
	bunch := Bunch{
		Kind: BunchAck,
	}

	hasID := true

	if layout.AckHasIDFlag {
		var err error

		if hasID, err = reader.ReadBit(); err != nil {
			return bunch, fmt.Errorf("truncated ACK id presence flag: %w", err)
		}
	}

	if hasID {
		id, err := reader.ReadBits(layout.AckIDBits)
		if err != nil {
			return bunch, fmt.Errorf("truncated ACK packet id: %w", err)
		}

		bunch.AckPacketID = id
	}

	return bunch, nil
}

func parseDataBunch(reader *BitReader, layout Layout) (Bunch, error) {
	bunch := Bunch{
		Kind: BunchData,
	}

	hasOpenClose, err := reader.ReadBit()
	if err != nil {
		return bunch, fmt.Errorf("truncated open/close presence flag: %w", err)
	}

	if hasOpenClose {
		if bunch.Open, err = reader.ReadBit(); err != nil {
			return bunch, fmt.Errorf("truncated open flag: %w", err)
		}

		if bunch.Close, err = reader.ReadBit(); err != nil {
			return bunch, fmt.Errorf("truncated close flag: %w", err)
		}
	}

	if bunch.Reliable, err = reader.ReadBit(); err != nil {
		return bunch, fmt.Errorf("truncated reliability flag: %w", err)
	}

	value, err := reader.ReadBits(layout.ChannelIndexBits)
	if err != nil {
		return bunch, fmt.Errorf("truncated channel index: %w", err)
	}

	bunch.ChannelIndex = uint16(value)

	if bunch.Reliable {
		if value, err = reader.ReadBits(layout.SequenceBits); err != nil {
			return bunch, fmt.Errorf("truncated channel sequence: %w", err)
		}

		bunch.ChannelSequence = uint16(value)
	}

	if bunch.Reliable || bunch.Open {
		if value, err = reader.ReadBits(layout.ChannelTypeBits); err != nil {
			return bunch, fmt.Errorf("truncated channel type: %w", err)
		}

		bunch.ChannelType = uint8(value)
		bunch.HasChannelType = true
	}

	if value, err = reader.ReadBits(layout.BunchSizeBits); err != nil {
		return bunch, fmt.Errorf("truncated bunch data length: %w", err)
	}

	bunch.DataBitCount = uint16(value)
	bunch.DataBitOffset = reader.Tell()

	if int(bunch.DataBitCount) > reader.Remaining() {
		return bunch, fmt.Errorf(
			"bunch data exceeds packet payload: data=%d remaining=%d",
			bunch.DataBitCount,
			reader.Remaining(),
		)
	}

	bunch.RawData = ExtractBits(
		reader.Data(),
		bunch.DataBitOffset,
		int(bunch.DataBitCount),
	)

	if err := reader.Skip(int(bunch.DataBitCount)); err != nil {
		return bunch, fmt.Errorf("failed to advance over bunch data: %w", err)
	}

	return bunch, nil
}
