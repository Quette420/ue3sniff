// Package capture opens a live interface or a capture file through
// libpcap / Npcap.
package capture

import (
	"fmt"
	"strconv"

	"github.com/google/gopacket/pcap"
)

func ListDevices() ([]pcap.Interface, error) {
	devices, err := pcap.FindAllDevs()
	if err != nil {
		return nil, err
	}

	if len(devices) == 0 {
		return nil, fmt.Errorf("no network interfaces found (is Npcap/libpcap installed and are you running elevated?)")
	}

	return devices, nil
}

// ResolveDevice accepts either a device index as printed by ListDevices or
// a device name such as \Device\NPF_Loopback.
func ResolveDevice(value string) (string, error) {
	devices, err := ListDevices()
	if err != nil {
		return "", err
	}

	if index, err := strconv.Atoi(value); err == nil {
		if index < 0 || index >= len(devices) {
			return "", fmt.Errorf("device index %d out of range", index)
		}

		return devices[index].Name, nil
	}

	for _, device := range devices {
		if device.Name == value {
			return device.Name, nil
		}
	}

	return "", fmt.Errorf("device not found: %s", value)
}

func OpenLive(device string) (*pcap.Handle, error) {
	name, err := ResolveDevice(device)
	if err != nil {
		return nil, err
	}

	return pcap.OpenLive(name, 65535, true, pcap.BlockForever)
}

func OpenFile(path string) (*pcap.Handle, error) {
	return pcap.OpenOffline(path)
}

// Filter builds a BPF expression for one game server port and, optionally,
// a single client port. Both directions are always captured.
func Filter(serverPort, clientPort int) string {
	if clientPort == 0 {
		return fmt.Sprintf("udp port %d", serverPort)
	}

	return fmt.Sprintf(
		"udp and ((src port %d and dst port %d) or (src port %d and dst port %d))",
		serverPort,
		clientPort,
		clientPort,
		serverPort,
	)
}
