/**
 * Traffic Classification.
 *
 * Categorizes network flows into high-level traffic classes
 * (streaming, social media, gaming, etc.) for analysis and reporting.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"strings"

	"github.com/kleaSCM/netscope/internal/models"
)

// TrafficClassifier categorizes flows into traffic types.
type TrafficClassifier struct {
	appIdentifier *ApplicationIdentifier
}

// Creates a new classifier that uses application identification for better accuracy.
func NewTrafficClassifier(appID *ApplicationIdentifier) *TrafficClassifier {
	return &TrafficClassifier{
		appIdentifier: appID,
	}
}

// Determines the traffic category for a flow.
// Returns category name or "Unknown" if unable to classify.
func (tc *TrafficClassifier) Classify(flow *models.Flow) string {
	// Use application name if available
	app := flow.Application
	if app == "" && tc.appIdentifier != nil {
		app = tc.appIdentifier.Identify(flow)
	}

	// Classify based on application
	if app != "" {
		if class := tc.classifyByApp(app); class != "" {
			return class
		}
	}

	// Classify based on domain
	if flow.DstDomain != "" {
		if class := tc.classifyByDomain(flow.DstDomain); class != "" {
			return class
		}
	}

	// Classify based on port and protocol
	if class := tc.classifyByPort(int(flow.Key.DstPort), flow.Protocol); class != "" {
		return class
	}

	return "Unknown"
}

// Application name provides the most accurate classification signal.
func (tc *TrafficClassifier) classifyByApp(app string) string {
	app = strings.ToLower(app)

	// Video Streaming
	streamingApps := []string{"youtube", "netflix", "twitch", "hulu", "disney", "prime video", "vimeo"}
	for _, s := range streamingApps {
		if strings.Contains(app, s) {
			return "Streaming"
		}
	}

	// Music Streaming
	musicApps := []string{"spotify", "apple music", "pandora", "soundcloud", "tidal"}
	for _, m := range musicApps {
		if strings.Contains(app, m) {
			return "Music"
		}
	}

	// Social Media
	socialApps := []string{"facebook", "instagram", "twitter", "tiktok", "linkedin", "snapchat", "reddit", "pinterest"}
	for _, s := range socialApps {
		if strings.Contains(app, s) {
			return "Social Media"
		}
	}

	// Messaging
	messagingApps := []string{"whatsapp", "telegram", "discord", "slack", "signal", "messenger"}
	for _, m := range messagingApps {
		if strings.Contains(app, m) {
			return "Messaging"
		}
	}

	// Gaming
	gamingApps := []string{"steam", "epic games", "riot", "league", "valorant", "blizzard", "battle.net", "minecraft", "xbox", "playstation"}
	for _, g := range gamingApps {
		if strings.Contains(app, g) {
			return "Gaming"
		}
	}

	// Cloud Storage
	cloudApps := []string{"dropbox", "google drive", "onedrive", "icloud", "box"}
	for _, c := range cloudApps {
		if strings.Contains(app, c) {
			return "Cloud Storage"
		}
	}

	// Email
	emailApps := []string{"gmail", "outlook", "yahoo mail", "smtp", "imap", "pop3"}
	for _, e := range emailApps {
		if strings.Contains(app, e) {
			return "Email"
		}
	}

	// Remote Access
	remoteApps := []string{"rdp", "vnc", "ssh", "telnet", "teamviewer", "anydesk"}
	for _, r := range remoteApps {
		if strings.Contains(app, r) {
			return "Remote Access"
		}
	}

	// VoIP
	voipApps := []string{"sip", "zoom", "skype", "teams", "webex"}
	for _, v := range voipApps {
		if strings.Contains(app, v) {
			return "VoIP"
		}
	}

	// Web Browsing (generic)
	if strings.Contains(app, "http") || strings.Contains(app, "chrome") || strings.Contains(app, "firefox") || strings.Contains(app, "safari") {
		return "Web Browsing"
	}

	return ""
}

// Domain patterns help classify when application name is unavailable.
func (tc *TrafficClassifier) classifyByDomain(domain string) string {
	domain = strings.ToLower(domain)

	// CDN and infrastructure (usually indicates web content)
	cdnDomains := []string{"cloudflare", "akamai", "fastly", "cloudfront", "cdn"}
	for _, cdn := range cdnDomains {
		if strings.Contains(domain, cdn) {
			return "Web Browsing"
		}
	}

	return ""
}

// Port-based classification provides fallback when other signals are missing.
func (tc *TrafficClassifier) classifyByPort(port int, protocol string) string {
	switch port {
	case 53:
		return "DNS"
	case 80, 443, 8080, 8443:
		return "Web Browsing"
	case 25, 587, 465, 143, 993, 110, 995:
		return "Email"
	case 21, 22, 989, 990:
		return "File Transfer"
	case 3389, 5900, 23:
		return "Remote Access"
	case 5060, 5061:
		return "VoIP"
	case 3000, 6881, 6882, 6883, 6884, 6885, 6886, 6887, 6888, 6889:
		return "File Sharing"
	}

	// Gaming ports (common ranges)
	if port >= 27000 && port <= 27050 {
		return "Gaming"
	}
	if port >= 3074 && port <= 3076 {
		return "Gaming"
	}

	return ""
}
