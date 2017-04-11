package sniffer

import (
	"github.com/tsg/gopacket"
	"time"
	//	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
)

// Worker callback handler
type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
}

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
