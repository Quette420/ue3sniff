// Command ue3sniff captures Unreal Engine 3 UDP game traffic, decrypts it
// when the game requires it and decodes bunches and RPC fields according to
// a game profile.
package main

import (
	"encoding/hex"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
	"github.com/google/gopacket/pcap"

	"github.com/quette/ue3sniff/capture"
	"github.com/quette/ue3sniff/crypto"
	"github.com/quette/ue3sniff/logger"
	"github.com/quette/ue3sniff/profile"
	"github.com/quette/ue3sniff/ue3"
)

type options struct {
	profile string

	device      string
	pcapFile    string
	listDevices bool

	serverPort int
	clientPort int
	filter     string

	key string

	watch  string
	all    bool
	format string

	logLevel string
}

func parseFlags() options {
	var o options

	flag.StringVar(&o.profile, "profile", "ue3", "game profile: built-in name ("+strings.Join(profile.Builtin(), ", ")+") or path to a JSON file")

	flag.StringVar(&o.device, "device", "", "capture interface name or index (see -list-devices)")
	flag.StringVar(&o.pcapFile, "pcap", "", "read packets from a .pcap/.pcapng file instead of a live interface")
	flag.BoolVar(&o.listDevices, "list-devices", false, "list capture interfaces and exit")

	flag.IntVar(&o.serverPort, "server-port", 0, "game server UDP port")
	flag.IntVar(&o.clientPort, "client-port", 0, "game client UDP port (optional, narrows the filter to one session)")
	flag.StringVar(&o.filter, "filter", "", "custom BPF filter (overrides -server-port/-client-port)")

	flag.StringVar(&o.key, "key", "", "session key as hex, for profiles with a cipher")

	flag.StringVar(&o.watch, "watch", "", "only print matching fields: watch groups, field names, Class.Field, indices or ranges, comma separated (implies -all)")
	flag.BoolVar(&o.all, "all", false, "decode every packet instead of only the first packet of each UDP length")
	flag.StringVar(&o.format, "format", "text", "output format: text or json (JSON Lines)")

	flag.StringVar(&o.logLevel, "log-level", "info", "diagnostics level on stderr: error, info, debug, trace")

	flag.Usage = func() {
		fmt.Fprintf(flag.CommandLine.Output(), "Usage: ue3sniff [flags]\n\nFlags:\n")
		flag.PrintDefaults()
	}

	flag.Parse()

	return o
}

func main() {
	if err := run(parseFlags()); err != nil {
		fmt.Fprintln(os.Stderr, "ue3sniff:", err)
		os.Exit(1)
	}
}

func run(o options) error {
	appLogger, err := logger.New(o.logLevel, os.Stderr)
	if err != nil {
		return err
	}

	if o.listDevices || (o.device == "" && o.pcapFile == "") {
		return listDevices()
	}

	game, err := profile.Load(o.profile)
	if err != nil {
		return err
	}

	appLogger.Info("Profile: %s", game.Name)

	cipher, err := crypto.New(game.Cipher, o.key)
	if err != nil {
		return err
	}

	if cipher == nil && game.Cipher.Algorithm != "" && game.Cipher.Algorithm != "none" {
		appLogger.Info("No -key given: %s traffic will only parse if it is plaintext", game.Cipher.Algorithm)
	}

	printer, err := NewPrinter(o.format, os.Stdout)
	if err != nil {
		return err
	}

	s := &session{
		options: o,
		profile: game,
		cipher:  cipher,
		log:     appLogger,
		printer: printer,
		stats:   NewPacketStatsCache(),

		channelTypes: make(map[uint16]uint8),
	}

	if o.watch != "" {
		if s.watch, err = game.NewSelector(o.watch); err != nil {
			return err
		}
	}

	filter := o.filter

	if filter == "" {
		if o.serverPort == 0 {
			return fmt.Errorf("-server-port (or -filter) is required")
		}

		filter = capture.Filter(o.serverPort, o.clientPort)
	}

	var handle *pcap.Handle

	if o.pcapFile != "" {
		handle, err = capture.OpenFile(o.pcapFile)
		appLogger.Info("Reading %s", o.pcapFile)
	} else {
		handle, err = capture.OpenLive(o.device)
		appLogger.Info("Device: %s", o.device)
	}

	if err != nil {
		return err
	}

	defer handle.Close()

	if err := handle.SetBPFFilter(filter); err != nil {
		return fmt.Errorf("BPF filter %q: %w", filter, err)
	}

	appLogger.Info("BPF filter: %s", filter)

	signals := make(chan os.Signal, 1)
	signal.Notify(signals, os.Interrupt, syscall.SIGTERM)

	go func() {
		<-signals
		appLogger.Info("Stopping...")
		handle.Close()
	}()

	source := gopacket.NewPacketSource(handle, handle.LinkType())

	appLogger.Info("Listening...")

	for captured := range source.Packets() {
		udp, ok := captured.Layer(layers.LayerTypeUDP).(*layers.UDP)
		if !ok || len(udp.Payload) == 0 {
			continue
		}

		s.handle(captured.Metadata().Timestamp, udp)
	}

	s.stats.Dump(appLogger)

	return nil
}

func listDevices() error {
	devices, err := capture.ListDevices()
	if err != nil {
		return err
	}

	fmt.Println("Available interfaces:")

	for i, d := range devices {
		fmt.Printf("[%d] %s", i, d.Name)

		if d.Description != "" {
			fmt.Printf("  (%s)", d.Description)
		}

		fmt.Println()

		for _, addr := range d.Addresses {
			fmt.Printf("      %s\n", addr.IP)
		}
	}

	fmt.Println("\nSelect one with -device <index|name>.")

	return nil
}

type session struct {
	options options
	profile *profile.Profile
	cipher  crypto.Cipher
	log     *logger.Logger
	printer Printer
	stats   *PacketStatsCache
	watch   *profile.Selector

	// channelTypes remembers the type announced by reliable/open bunches,
	// so later unreliable bunches on the channel can be labelled.
	channelTypes map[uint16]uint8
}

// decode parses a payload as plaintext and/or ciphertext. When watching an
// established (encrypted) session the cipher is tried first; otherwise
// plaintext first, which keeps unencrypted login traffic readable.
func (s *session) decode(payload []byte) (ue3.Packet, bool, error) {
	tryCipher := func() (ue3.Packet, bool, error) {
		decrypted := append([]byte(nil), payload...)

		if !s.cipher.Decrypt(decrypted) {
			return ue3.Packet{}, false, fmt.Errorf("payload length %d not decryptable", len(payload))
		}

		packet, err := ue3.ParsePacket(decrypted, s.profile.Layout)

		return packet, err == nil, err
	}

	if s.cipher == nil {
		packet, err := ue3.ParsePacket(payload, s.profile.Layout)
		return packet, false, err
	}

	if s.watch != nil {
		if packet, ok, _ := tryCipher(); ok {
			return packet, true, nil
		}

		packet, err := ue3.ParsePacket(payload, s.profile.Layout)

		return packet, false, err
	}

	if packet, err := ue3.ParsePacket(payload, s.profile.Layout); err == nil {
		return packet, false, nil
	}

	packet, ok, err := tryCipher()
	if err != nil {
		err = fmt.Errorf("after decrypt: %w", err)
	}

	return packet, ok, err
}

func (s *session) direction(udp *layers.UDP) string {
	server := layers.UDPPort(s.options.serverPort)

	switch {
	case server != 0 && udp.DstPort == server:
		return "C2S"
	case server != 0 && udp.SrcPort == server:
		return "S2C"
	}

	return fmt.Sprintf("%d->%d", udp.SrcPort, udp.DstPort)
}

func (s *session) handle(timestamp time.Time, udp *layers.UDP) {
	payload := udp.Payload

	packet, decrypted, err := s.decode(payload)

	var packetID *uint32

	if err == nil {
		packetID = &packet.PacketID
	}

	isNewLength := s.stats.Observe(payload, packetID, err)

	if err != nil {
		s.log.Debug("UE3 parse failed: length=%d error=%v", len(payload), err)
		return
	}

	s.log.Debug(
		"UE3 parse OK: length=%d packet=%d bunches=%d decrypted=%v",
		len(payload),
		packet.PacketID,
		len(packet.Bunches),
		decrypted,
	)

	inspect := s.watch != nil || s.options.all || isNewLength

	direction := s.direction(udp)

	for i, bunch := range packet.Bunches {
		s.trackChannel(bunch)

		if !inspect {
			continue
		}

		s.inspectBunch(timestamp, direction, packet.PacketID, i, bunch)
	}
}

func (s *session) trackChannel(bunch ue3.Bunch) {
	if bunch.Kind != ue3.BunchData {
		return
	}

	if bunch.HasChannelType {
		s.channelTypes[bunch.ChannelIndex] = bunch.ChannelType
	}
}

func (s *session) inspectBunch(
	timestamp time.Time,
	direction string,
	packetID uint32,
	index int,
	bunch ue3.Bunch,
) {
	if bunch.Kind == ue3.BunchAck {
		s.log.Trace("%s pkt=%d bunch=%d ACK %d", direction, packetID, index, bunch.AckPacketID)
		return
	}

	event := Event{
		Time:      timestamp,
		Direction: direction,
		Packet:    packetID,
		Bunch:     index,
		Channel:   bunch.ChannelIndex,
		Sequence:  bunch.ChannelSequence,
		Reliable:  bunch.Reliable,
		Open:      bunch.Open,
		Close:     bunch.Close,
		BunchBits: int(bunch.DataBitCount),
		BunchRaw:  hex.EncodeToString(bunch.RawData),
	}

	if channelType, ok := s.channelTypes[bunch.ChannelIndex]; ok {
		event.ChannelType = s.profile.ChannelTypeName(channelType)
	}

	if bunch.Close {
		delete(s.channelTypes, bunch.ChannelIndex)
	}

	class := s.profile.ClassForChannel(bunch.ChannelIndex)

	if class == nil {
		// Nothing to decode on this channel; in exploratory mode show the
		// raw bunch so it can be studied.
		if s.watch == nil && bunch.DataBitCount > 0 {
			s.printer.Print(event)
		}

		return
	}

	fields, err := class.DecodeBunch(bunch)

	for i := range fields {
		field := fields[i]

		if s.watch != nil && !s.watch.Match(field.Class, field.Index, field.Name) {
			continue
		}

		fieldEvent := event
		fieldEvent.Field = &field
		fieldEvent.FieldRaw = hexOrEmpty(field.RawBits)

		// The decode error belongs to the last field reached.
		if err != nil && i == len(fields)-1 {
			fieldEvent.Error = err.Error()
		}

		s.printer.Print(fieldEvent)
	}

	if err != nil && len(fields) == 0 && s.watch == nil {
		event.Error = err.Error()
		s.printer.Print(event)
	}
}
