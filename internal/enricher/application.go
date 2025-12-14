/**
 * Application Identification.
 *
 * Identifies specific applications by combining multiple signals:
 * port numbers, domain patterns, JA3 fingerprints, and protocol analysis.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"strings"

	"github.com/kleaSCM/netscope/internal/models"
)

// ApplicationIdentifier identifies applications from network flows.
type ApplicationIdentifier struct {
	ja3DB          *JA3Database
	portMap        map[int]string
	domainPatterns map[string]string
}

// Creates a new identifier with default mappings for common services.
func NewApplicationIdentifier(ja3DB *JA3Database) *ApplicationIdentifier {
	ai := &ApplicationIdentifier{
		ja3DB:          ja3DB,
		portMap:        make(map[int]string),
		domainPatterns: make(map[string]string),
	}
	ai.loadDefaults()
	return ai
}

// Determines the application name for a flow using multiple signals.
// Returns the most confident match or empty string if unknown.
func (ai *ApplicationIdentifier) Identify(flow *models.Flow) string {
	// Priority 1: JA3 fingerprint (most specific)
	if flow.JA3 != "" && ai.ja3DB != nil {
		if app := ai.ja3DB.Lookup(flow.JA3); app != "" {
			return app
		}
	}

	// Priority 2: Domain pattern matching (very reliable)
	if flow.DstDomain != "" {
		if app := ai.identifyByDomain(flow.DstDomain); app != "" {
			return app
		}
	}

	// Priority 3: TLS SNI (fallback for domain)
	if flow.TLSSNI != "" {
		if app := ai.identifyByDomain(flow.TLSSNI); app != "" {
			return app
		}
	}

	// Priority 4: Port-based detection (least specific)
	dstPort := int(flow.Key.DstPort)
	if app := ai.identifyByPort(dstPort, flow.Protocol); app != "" {
		return app
	}

	return ""
}

// Port-based identification provides fallback when domain/JA3 unavailable.
func (ai *ApplicationIdentifier) identifyByPort(port int, protocol string) string {
	if app, ok := ai.portMap[port]; ok {
		return app
	}
	return ""
}

// Domain pattern matching is highly reliable for identifying specific services.
func (ai *ApplicationIdentifier) identifyByDomain(domain string) string {
	domain = strings.ToLower(domain)

	// Exact match first
	if app, ok := ai.domainPatterns[domain]; ok {
		return app
	}

	// Pattern matching (suffix matching for subdomains)
	for pattern, app := range ai.domainPatterns {
		if strings.HasSuffix(domain, pattern) {
			return app
		}
	}

	return ""
}

// Populates port and domain mappings for 50+ popular services.
func (ai *ApplicationIdentifier) loadDefaults() {
	// Port-based identification
	ai.portMap = map[int]string{
		// Web
		80:   "HTTP",
		443:  "HTTPS",
		8080: "HTTP-Alt",
		8443: "HTTPS-Alt",

		// Email
		25:  "SMTP",
		587: "SMTP-Submission",
		465: "SMTPS",
		143: "IMAP",
		993: "IMAPS",
		110: "POP3",
		995: "POP3S",

		// File Transfer
		21:   "FTP",
		22:   "SSH/SFTP",
		989:  "FTPS-Data",
		990:  "FTPS",
		3000: "BitTorrent",

		// Remote Access
		3389: "RDP",
		5900: "VNC",
		23:   "Telnet",

		// VoIP
		5060: "SIP",
		5061: "SIP-TLS",

		// DNS
		53: "DNS",

		// Gaming (common ports)
		27015: "Steam",
		3074:  "Xbox Live",
		3478:  "PlayStation Network",
	}

	// Domain-based identification
	ai.domainPatterns = map[string]string{
		// Video Streaming
		"youtube.com":     "YouTube",
		"googlevideo.com": "YouTube",
		"ytimg.com":       "YouTube",
		"netflix.com":     "Netflix",
		"nflxvideo.net":   "Netflix",
		"nflximg.net":     "Netflix",
		"nflxext.com":     "Netflix",
		"twitch.tv":       "Twitch",
		"ttvnw.net":       "Twitch",
		"hulu.com":        "Hulu",
		"hulustream.com":  "Hulu",
		"disneyplus.com":  "Disney+",
		"primevideo.com":  "Amazon Prime Video",
		"amazonvideo.com": "Amazon Prime Video",

		// Music Streaming
		"spotify.com":    "Spotify",
		"scdn.co":        "Spotify",
		"apple.com":      "Apple Music",
		"mzstatic.com":   "Apple Music",
		"pandora.com":    "Pandora",
		"soundcloud.com": "SoundCloud",

		// Social Media
		"facebook.com":     "Facebook",
		"fbcdn.net":        "Facebook",
		"instagram.com":    "Instagram",
		"cdninstagram.com": "Instagram",
		"twitter.com":      "Twitter",
		"twimg.com":        "Twitter",
		"tiktok.com":       "TikTok",
		"tiktokcdn.com":    "TikTok",
		"linkedin.com":     "LinkedIn",
		"licdn.com":        "LinkedIn",
		"snapchat.com":     "Snapchat",
		"sc-cdn.net":       "Snapchat",
		"reddit.com":       "Reddit",
		"redd.it":          "Reddit",
		"redditstatic.com": "Reddit",

		// Messaging
		"whatsapp.com":   "WhatsApp",
		"whatsapp.net":   "WhatsApp",
		"telegram.org":   "Telegram",
		"t.me":           "Telegram",
		"discord.com":    "Discord",
		"discordapp.com": "Discord",
		"slack.com":      "Slack",
		"slack-edge.com": "Slack",

		// Cloud Storage
		"dropbox.com":       "Dropbox",
		"dropboxapi.com":    "Dropbox",
		"drive.google.com":  "Google Drive",
		"docs.google.com":   "Google Docs",
		"onedrive.live.com": "OneDrive",
		"1drv.com":          "OneDrive",
		"icloud.com":        "iCloud",

		// Email
		"gmail.com":        "Gmail",
		"googlemail.com":   "Gmail",
		"outlook.com":      "Outlook",
		"outlook.live.com": "Outlook",
		"yahoo.com":        "Yahoo Mail",
		"ymail.com":        "Yahoo Mail",

		// Gaming
		"steampowered.com":    "Steam",
		"steamcommunity.com":  "Steam",
		"epicgames.com":       "Epic Games",
		"riotgames.com":       "Riot Games",
		"leagueoflegends.com": "League of Legends",
		"valorant.com":        "Valorant",
		"blizzard.com":        "Blizzard",
		"battle.net":          "Battle.net",
		"minecraft.net":       "Minecraft",
		"mojang.com":          "Minecraft",

		// CDN / Infrastructure
		"cloudflare.com":        "Cloudflare",
		"akamai.net":            "Akamai CDN",
		"fastly.net":            "Fastly CDN",
		"amazonaws.com":         "AWS",
		"cloudfront.net":        "AWS CloudFront",
		"googleusercontent.com": "Google Services",
	}
}
