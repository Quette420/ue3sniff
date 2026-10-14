package main

import (
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/quette/ue3sniff/logger"
)

type PacketStats struct {
	Count int

	// First packet seen for this UDP payload length.
	FirstPayload []byte

	ParsedPackets int
	FailedPackets int

	PacketIDs map[uint32]int
}

type PacketStatsCache struct {
	// UDP payload length -> statistics
	Packets map[int]*PacketStats
}

func NewPacketStatsCache() *PacketStatsCache {
	return &PacketStatsCache{
		Packets: make(map[int]*PacketStats),
	}
}

// Observe records a packet and reports whether its length is new.
func (c *PacketStatsCache) Observe(
	payload []byte,
	packetID *uint32,
	parseErr error,
) bool {
	length := len(payload)

	stats, exists := c.Packets[length]

	if !exists {
		stats = &PacketStats{
			FirstPayload: append([]byte(nil), payload...),
			PacketIDs:    make(map[uint32]int),
		}

		c.Packets[length] = stats
	}

	stats.Count++

	if packetID != nil {
		stats.PacketIDs[*packetID]++
	}

	if parseErr == nil {
		stats.ParsedPackets++
	} else {
		stats.FailedPackets++
	}

	return !exists
}

func (c *PacketStatsCache) Lengths() []int {
	result := make([]int, 0, len(c.Packets))

	for length := range c.Packets {
		result = append(result, length)
	}

	sort.Ints(result)

	return result
}

func (c *PacketStatsCache) Dump(appLogger *logger.Logger) {
	appLogger.Debug("Packet statistics by UDP payload length:")

	for _, length := range c.Lengths() {
		stats := c.Packets[length]

		ids := make([]uint32, 0, len(stats.PacketIDs))

		for id := range stats.PacketIDs {
			ids = append(ids, id)
		}

		sort.Slice(ids, func(i, j int) bool {
			return ids[i] < ids[j]
		})

		packetIDs := make([]string, len(ids))

		for i, id := range ids {
			packetIDs[i] = fmt.Sprintf("%d(%d)", id, stats.PacketIDs[id])
		}

		appLogger.Debug(
			"%d bytes: count=%d parsed=%d failed=%d packetIDs=[%s]",
			length,
			stats.Count,
			stats.ParsedPackets,
			stats.FailedPackets,
			strings.Join(packetIDs, ", "),
		)

		appLogger.Trace(
			"%d bytes first payload:\n%s",
			length,
			hex.Dump(stats.FirstPayload),
		)
	}
}
