/**
 * Packet Model.
 *
 * Encapsulates parsed packet data from various network layers (L2-L7)
 * into a unified structure for processing and storage.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package models

import (
	"time"
)

// Represents a parsed network packet with layered data.
type Packet struct {
	Timestamp time.Time
	Length    int
	Layer2    *Layer2
	Layer3    *Layer3
	Layer4    *Layer4
	DNS       *DNS
	TLS       *TLS
	Metadata  map[string]interface{}
}

// Represents DNS layer information extracted from the packet.
type DNS struct {
	Query     string
	Answers   []DNSAnswer
	ResCode   string
	Type      string // Query or Response
	QueryType string // A, AAAA, etc.
}

// Represents a single DNS answer record provided in a response.
type DNSAnswer struct {
	Name  string
	Type  string
	IP    string
	TTL   uint32
	CNAME string
}

// Represents TLS layer information, such as SNI and handshake details.
type TLS struct {
	SNI         string
	Version     string
	CipherSuite string
	Handshake   bool
}

// Represents Data Link Layer (Ethernet) information.
type Layer2 struct {
	SrcMAC    string
	DstMAC    string
	EtherType string
}

// Represents Network Layer (IP) information.
type Layer3 struct {
	SrcIP    string
	DstIP    string
	Version  string // IPv4 or IPv6
	Protocol string // TCP, UDP, ICMP, etc.
	TTL      uint8  // Time to Live (or Hop Limit)
}

// Represents Transport Layer (TCP/UDP) information.
type Layer4 struct {
	SrcPort  int
	DstPort  int
	Protocol string // TCP or UDP
	Flags    []string
	Seq      uint32
	Ack      uint32
}
