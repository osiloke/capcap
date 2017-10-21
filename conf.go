package capcap

import (
	"time"
)

type Conf struct {
	MetricsAddress string

	Iface              []string
	Filter             string
	PacketTimeInterval time.Duration
	FlowTimeout        time.Duration
	FlowByteCutoff     uint
	FlowPacketCutoff   uint
	WriteOutputPath    string
	WriteCompressed    bool

	RotationInterval time.Duration
}
