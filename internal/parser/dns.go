/**
 * DNS Protocol Parser.
 *
 * Decodes DNS queries and responses, extracting QNAMEs, answers,
 * and related metadata for correlation and analysis.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package parser

import (
	"fmt"
	"time"

	"github.com/google/gopacket"
	"github.com/google/gopacket/layers"
)

// Represents a DNS query.
type DNSQuery struct {
	Timestamp     time.Time
	TransactionID uint16
	QueryName     string
	QueryType     string
	SrcIP         string
	DstIP         string
}

// Represents a DNS response.
type DNSResponse struct {
	Timestamp     time.Time
	TransactionID uint16
	QueryName     string
	Answers       []DNSAnswer
	ResponseCode  string
	SrcIP         string
	DstIP         string
}

// Represents a single DNS answer record.
type DNSAnswer struct {
	Name  string
	Type  string
	IP    string
	TTL   uint32
	CNAME string
}

// Extracts DNS information from a packet.
func ParseDNS(packet gopacket.Packet) (*DNSQuery, *DNSResponse, error) {
	// Check if packet has DNS layer
	dnsLayer := packet.Layer(layers.LayerTypeDNS)
	if dnsLayer == nil {
		return nil, nil, fmt.Errorf("no DNS layer found")
	}

	dns, _ := dnsLayer.(*layers.DNS)

	// Extract source and destination IPs
	var srcIP, dstIP string
	if ipLayer := packet.Layer(layers.LayerTypeIPv4); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv4)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	} else if ipLayer := packet.Layer(layers.LayerTypeIPv6); ipLayer != nil {
		ip, _ := ipLayer.(*layers.IPv6)
		srcIP = ip.SrcIP.String()
		dstIP = ip.DstIP.String()
	}

	timestamp := packet.Metadata().Timestamp

	// Check if this is a query or response
	if !dns.QR {
		// This is a query
		return parseDNSQuery(dns, timestamp, srcIP, dstIP), nil, nil
	} else {
		// This is a response
		return nil, parseDNSResponse(dns, timestamp, srcIP, dstIP), nil
	}
}

func parseDNSQuery(dns *layers.DNS, timestamp time.Time, srcIP, dstIP string) *DNSQuery {
	query := &DNSQuery{
		Timestamp:     timestamp,
		TransactionID: dns.ID,
		SrcIP:         srcIP,
		DstIP:         dstIP,
	}

	// Extract query information
	if len(dns.Questions) > 0 {
		q := dns.Questions[0]
		query.QueryName = string(q.Name)
		query.QueryType = q.Type.String()
	}

	return query
}

func parseDNSResponse(dns *layers.DNS, timestamp time.Time, srcIP, dstIP string) *DNSResponse {
	response := &DNSResponse{
		Timestamp:     timestamp,
		TransactionID: dns.ID,
		ResponseCode:  dns.ResponseCode.String(),
		Answers:       make([]DNSAnswer, 0),
		SrcIP:         srcIP,
		DstIP:         dstIP,
	}

	// Extract query name from questions
	if len(dns.Questions) > 0 {
		response.QueryName = string(dns.Questions[0].Name)
	}

	// Parse answer records
	for _, answer := range dns.Answers {
		dnsAnswer := DNSAnswer{
			Name: string(answer.Name),
			Type: answer.Type.String(),
			TTL:  answer.TTL,
		}

		// Extract IP address or CNAME based on record type
		switch answer.Type {
		case layers.DNSTypeA:
			dnsAnswer.IP = answer.IP.String()
		case layers.DNSTypeAAAA:
			dnsAnswer.IP = answer.IP.String()
		case layers.DNSTypeCNAME:
			dnsAnswer.CNAME = string(answer.CNAME)
		case layers.DNSTypePTR:
			dnsAnswer.CNAME = string(answer.PTR)
		}

		response.Answers = append(response.Answers, dnsAnswer)
	}

	return response
}

// Returns a human-readable string for a DNS query.
func (q *DNSQuery) FormatQuery() string {
	return fmt.Sprintf("DNS Query: %s (%s) [ID: %d]",
		q.QueryName, q.QueryType, q.TransactionID)
}

// Returns a human-readable string for a DNS response.
func (r *DNSResponse) FormatResponse() string {
	if r.ResponseCode != "No Error" {
		return fmt.Sprintf("DNS Response: %s - %s [ID: %d]",
			r.QueryName, r.ResponseCode, r.TransactionID)
	}

	if len(r.Answers) == 0 {
		return fmt.Sprintf("DNS Response: %s - No answers [ID: %d]",
			r.QueryName, r.TransactionID)
	}

	// Format first answer
	firstAnswer := r.Answers[0]
	var result string

	if firstAnswer.IP != "" {
		result = fmt.Sprintf("DNS Response: %s → %s",
			r.QueryName, firstAnswer.IP)
	} else if firstAnswer.CNAME != "" {
		result = fmt.Sprintf("DNS Response: %s → %s (CNAME)",
			r.QueryName, firstAnswer.CNAME)
	} else {
		result = fmt.Sprintf("DNS Response: %s (%s)",
			r.QueryName, firstAnswer.Type)
	}

	// Add additional answers if present
	if len(r.Answers) > 1 {
		result += fmt.Sprintf(" +%d more", len(r.Answers)-1)
	}

	result += fmt.Sprintf(" [ID: %d]", r.TransactionID)
	return result
}

// Returns detailed information about the DNS response.
func (r *DNSResponse) FormatVerbose() string {
	output := fmt.Sprintf("DNS Response [ID: %d]\n", r.TransactionID)
	output += fmt.Sprintf("  Query: %s\n", r.QueryName)
	output += fmt.Sprintf("  Response Code: %s\n", r.ResponseCode)
	output += fmt.Sprintf("  Answers: %d\n", len(r.Answers))

	for i, answer := range r.Answers {
		output += fmt.Sprintf("  [%d] %s (%s, TTL: %ds)\n",
			i+1, answer.Name, answer.Type, answer.TTL)
		if answer.IP != "" {
			output += fmt.Sprintf("      IP: %s\n", answer.IP)
		}
		if answer.CNAME != "" {
			output += fmt.Sprintf("      CNAME: %s\n", answer.CNAME)
		}
	}

	return output
}

// Checks if a packet contains DNS data.
func IsDNSPacket(packet gopacket.Packet) bool {
	return packet.Layer(layers.LayerTypeDNS) != nil
}
