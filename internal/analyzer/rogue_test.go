/**
 * Rogue AP Detection Tests.
 *
 * Unit tests verifying the detection logic for Evil Twins,
 * duplicates, and suspicious networks.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"strings"
	"testing"

	"github.com/kleaSCM/netscope/internal/models"
)

func TestDetectRogueAPs(t *testing.T) {
	tests := []struct {
		name     string
		aps      []*models.AccessPoint
		expected int
		msgCheck string
	}{
		{
			name: "No Rogues",
			aps: []*models.AccessPoint{
				{BSSID: "AA:BB:CC:DD:EE:01", SSID: "HomeWiFi", Encryption: "WPA2"},
				{BSSID: "AA:BB:CC:DD:EE:02", SSID: "OtherNet", Encryption: "WPA2"},
			},
			expected: 0,
		},
		{
			name: "Evil Twin (Secure + Open)",
			aps: []*models.AccessPoint{
				{BSSID: "AA:BB:CC:DD:EE:01", SSID: "Corporate", Encryption: "WPA2-Ent"},
				{BSSID: "11:22:33:44:55:66", SSID: "Corporate", Encryption: "Open"},
			},
			expected: 1,
			msgCheck: "Evil Twin",
		},
		{
			name: "Evil Twin (Secure + Empty Enc)",
			aps: []*models.AccessPoint{
				{BSSID: "AA:BB:CC:DD:EE:01", SSID: "Corporate", Encryption: "WPA2"},
				{BSSID: "11:22:33:44:55:66", SSID: "Corporate", Encryption: ""}, // Empty often implies Open
			},
			expected: 1,
			msgCheck: "Evil Twin",
		},
		{
			name: "Duplicate SSID (e.g. Mesh or multiple routers) - Warning",
			aps: []*models.AccessPoint{
				{BSSID: "AA:BB:CC:DD:EE:01", SSID: "HomeWiFi", Encryption: "WPA2"},
				{BSSID: "AA:BB:CC:DD:EE:02", SSID: "HomeWiFi", Encryption: "WPA2"},
			},
			expected: 2,
			msgCheck: "Multiple APs",
		},
		{
			name: "Suspicious Open Network (Keywords)",
			aps: []*models.AccessPoint{
				{BSSID: "AA:BB:CC:DD:EE:01", SSID: "CorpSecure", Encryption: "Open"},
			},
			expected: 1,
			msgCheck: "Suspicious Open Network",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			alerts := DetectRogueAPs(tt.aps)
			if len(alerts) != tt.expected {
				t.Errorf("expected %d alerts, got %d", tt.expected, len(alerts))
			}
			if len(alerts) > 0 && tt.msgCheck != "" {
				found := false
				for _, a := range alerts {
					if strings.Contains(a.Message, tt.msgCheck) {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected message containing '%s', got '%s'", tt.msgCheck, alerts[0].Message)
				}
			}
		})
	}
}
