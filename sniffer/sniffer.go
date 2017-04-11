package sniffer

import (
	"github.com/tsg/gopacket"
	"time"
	//	"github.com/tsg/gopacket/layers"
	"github.com/tsg/gopacket/pcap"
)

const (
	SNAPLEN = 65535
)

// Worker callback handler
type Worker interface {
	OnPacket(data []byte, ci *gopacket.CaptureInfo)
}

// Sniffer packet sniffer configuration
type Sniffer struct {
	pcapHandle *pcap.Handle
	//	afpacketHandle *afpacketHandle
	//	pfringHandle   *pfringHandle
	dumper *pcap.Dumper

	// iface to listen
	Interface string

	// capture filter
	Filter string

	// Decoder    *decoder.DecoderStruct
	Worker     Worker
	DataSource gopacket.PacketDataSource
}

// Init initialize sniffer
func (sniffer *Sniffer) Init() error {
	var err error
	sniffer.pcapHandle, err = pcap.OpenLive(
		sniffer.Interface,
		int32(SNAPLEN),
		true,
		500*time.Millisecond)
	if err != nil {
		return err
	}
	err = sniffer.pcapHandle.SetBPFFilter(sniffer.Filter)
	if err != nil {
		return err
	}

	sniffer.DataSource = gopacket.PacketDataSource(sniffer.pcapHandle)
	return nil
}
