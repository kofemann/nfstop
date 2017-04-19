package sniffer

import (
	"time"

	"github.com/tsg/gopacket/pcap"
)

// Sniffer packet sniffer configuration
type Sniffer struct {

	// iface to listen
	Interface string

	// capture filter
	Filter string

	// packet snapshot length
	Snaplen int
}

// Init initialize sniffer
func (sniffer *Sniffer) Init() (*pcap.Handle, error) {

	handle, err := pcap.OpenLive(
		sniffer.Interface,
		int32(sniffer.Snaplen),
		true,
		500*time.Millisecond)
	if err != nil {
		return nil, err
	}
	err = handle.SetBPFFilter(sniffer.Filter)
	if err != nil {
		return nil, err
	}

	return handle, nil
}
