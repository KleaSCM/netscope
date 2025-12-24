/**
 * Rogue AP Detection Logic.
 *
 * Analyzes discovered Access Points for signs of malicious activity,
 * such as Evil Twins (same SSID, different encryption) or suspicious
 * open networks.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"strings"

	"github.com/kleaSCM/netscope/internal/models"
)

// DetectRogueAPs scans the list of APs for potential threats.
func DetectRogueAPs(aps []*models.AccessPoint) []models.RogueAlert {
	var alerts []models.RogueAlert

	// Group APs by SSID to find duplicates/inconsistencies
	ssidMap := make(map[string][]*models.AccessPoint)
	for _, ap := range aps {
		if ap.SSID == "" || ap.SSID == "Hidden" {
			continue
		}
		ssidMap[ap.SSID] = append(ssidMap[ap.SSID], ap)
	}

	for ssid, group := range ssidMap {
		// Detect Evil Twin: Same SSID with mixed Encryption (e.g. WPA2 vs Open).
		// Attackers often spoof corporate SSIDs with Open authentication to harvest credentials.
		hasSecure := false
		hasOpen := false

		for _, ap := range group {
			enc := strings.ToLower(ap.Encryption)
			if strings.Contains(enc, "wpa") || strings.Contains(enc, "rsn") {
				hasSecure = true
			} else if strings.Contains(enc, "open") || enc == "" {
				hasOpen = true
			}
		}

		if hasSecure && hasOpen {
			for _, ap := range group {
				enc := strings.ToLower(ap.Encryption)
				if strings.Contains(enc, "open") || enc == "" {
					alerts = append(alerts, models.RogueAlert{
						BSSID:    ap.BSSID,
						SSID:     ap.SSID,
						Severity: "CRITICAL",
						Message:  "Evil Twin Detected: Open AP matching secure network SSID",
					})
				}
			}
		}

		// Detect Duplicate SSIDs: Multiple BSSIDs for the same network.
		// While this can indicate valid mesh networks, it is often a sign of a Rogue AP
		// if the environment is not expected to have multiple APs.
		if len(group) > 1 {
			// Avoid duplicate alerting if already flagged as Critical
			alreadyFlagged := false
			for _, alert := range alerts {
				if alert.SSID == ssid && alert.Severity == "CRITICAL" {
					alreadyFlagged = true
					break
				}
			}

			if !alreadyFlagged {
				for _, ap := range group {
					alerts = append(alerts, models.RogueAlert{
						BSSID:    ap.BSSID,
						SSID:     ap.SSID,
						Severity: "WARNING",
						Message:  "Multiple APs sharing SSID (Possible Rogue or Mesh)",
					})
				}
			}
		}
	}

	// Rule 3: Corporate Impersonation (Open networks with suspicious names)
	keywords := []string{"corp", "internal", "secure", "private", "staff", "admin"}
	for _, ap := range aps {
		enc := strings.ToLower(ap.Encryption)
		if strings.Contains(enc, "open") || enc == "" {
			normalizedSSID := strings.ToLower(ap.SSID)
			for _, key := range keywords {
				if strings.Contains(normalizedSSID, key) {
					// Check if already alerted
					alreadyFlagged := false
					for _, alert := range alerts {
						if alert.BSSID == ap.BSSID {
							alreadyFlagged = true
							break
						}
					}

					if !alreadyFlagged {
						alerts = append(alerts, models.RogueAlert{
							BSSID:    ap.BSSID,
							SSID:     ap.SSID,
							Severity: "CRITICAL",
							Message:  "Suspicious Open Network containing '" + key + "'",
						})
					}
					break // Only one keyword match needed
				}
			}
		}
	}

	return alerts
}
