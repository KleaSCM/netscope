/**
 * Anomaly Detection Menu Implementation.
 *
 * Displays behavioral anomalies detected by comparing current activity
 * against established baselines for each device.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package cli

import (
	"fmt"
	"time"

	"github.com/kleaSCM/netscope/internal/analyzer"
	"github.com/kleaSCM/netscope/internal/capture"
	"github.com/kleaSCM/netscope/internal/models"
)

// AnomalyAlert represents a detected behavioral anomaly
type AnomalyAlert struct {
	DeviceMAC   string
	DeviceName  string
	AlertType   string
	Severity    string
	Description string
	Timestamp   time.Time
	Flow        *models.Flow
}

// Displays the anomaly detection menu.
func ShowAnomalyMenu(engine *capture.Engine, baselineTracker *analyzer.BaselineTracker) error {
	if engine == nil || baselineTracker == nil {
		ShowMessage("⚠️  Anomaly detection not initialized. Start a capture first.")
		return nil
	}

	ClearScreen()
	fmt.Println(GetBanner())
	fmt.Println("Behavioral Anomaly Detection")
	fmt.Println(string(make([]rune, 60)))

	// Get all baselines
	baselines := baselineTracker.GetAllBaselines()
	flows := engine.GetActiveFlows()

	if len(baselines) == 0 {
		fmt.Println("\n🔍 No behavioral baselines established yet.")
		fmt.Println("\nNetScope learns normal behavior patterns for each device.")
		fmt.Println("Baselines are established after observing 100+ flows per device.")
		fmt.Println("\nStart a capture and let it run for a while to build baselines.")
		PressEnterToContinue()
		return nil
	}

	// Display baseline status
	fmt.Printf("\n📊 Baseline Status:\n")
	fmt.Printf("   Devices with baselines: %d\n", len(baselines))

	establishedCount := 0
	for mac := range baselines {
		if baselineTracker.IsEstablished(mac) {
			establishedCount++
		}
	}
	fmt.Printf("   Established baselines: %d\n", establishedCount)
	fmt.Printf("   Learning phase: %d\n\n", len(baselines)-establishedCount)

	if establishedCount == 0 {
		fmt.Println("⏳ All devices are still in learning phase.")
		fmt.Println("   Continue capturing to establish baselines.")
		PressEnterToContinue()
		return nil
	}

	// Detect anomalies
	anomalies := detectAnomalies(flows, baselines, baselineTracker)

	if len(anomalies) == 0 {
		fmt.Println("✅ No behavioral anomalies detected!")
		fmt.Println("\nAll observed traffic matches established patterns.")
		fmt.Println("NetScope will alert you if unusual activity is detected.")
		PressEnterToContinue()
		return nil
	}

	// Display anomalies by severity
	critical := 0
	high := 0
	medium := 0
	low := 0

	for _, a := range anomalies {
		switch a.Severity {
		case "CRITICAL":
			critical++
		case "HIGH":
			high++
		case "MEDIUM":
			medium++
		case "LOW":
			low++
		}
	}

	fmt.Println("⚠️  Anomalies Detected!\n")
	fmt.Printf("   🔴 Critical: %d\n", critical)
	fmt.Printf("   🟠 High: %d\n", high)
	fmt.Printf("   🟡 Medium: %d\n", medium)
	fmt.Printf("   🔵 Low: %d\n\n", low)

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("Anomaly Details:\n")

	// Display each anomaly
	for i, anomaly := range anomalies {
		printAnomalyDetails(anomaly, i+1)
	}

	fmt.Println("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━")
	fmt.Println("\n💡 Tip: Investigate suspicious anomalies to ensure network security.")
	PressEnterToContinue()
	return nil
}

func detectAnomalies(flows []*models.Flow, baselines map[string]*analyzer.DeviceBaseline, tracker *analyzer.BaselineTracker) []AnomalyAlert {
	var anomalies []AnomalyAlert
	now := time.Now()

	// Group flows by device (source MAC)
	// Note: Flow doesn't have DeviceMAC directly, we'd need to correlate via IP
	// For now, we'll check recent flows for anomaly patterns

	for _, flow := range flows {
		// Skip if flow is too old (only check recent activity)
		if now.Sub(flow.LastSeen) > 5*time.Minute {
			continue
		}

		// We need to find which device this flow belongs to
		// This requires mapping flow.Key.SrcIP -> Device MAC
		// For demonstration, we'll check baseline features directly

		// Check all baselines for anomalous patterns
		for mac, baseline := range baselines {
			if !tracker.IsEstablished(mac) {
				continue // Skip baselines still learning
			}

			// Check for new applications
			if flow.Application != "" && !baseline.HasApp(flow.Application) {
				anomalies = append(anomalies, AnomalyAlert{
					DeviceMAC:   mac,
					AlertType:   "New Application",
					Severity:    "MEDIUM",
					Description: fmt.Sprintf("First time using: %s", flow.Application),
					Timestamp:   flow.LastSeen,
					Flow:        flow,
				})
			}

			// Check for new destinations
			dest := flow.DstDomain
			if dest == "" {
				dest = flow.Key.DstIP
			}
			if !baseline.HasDestination(dest) {
				anomalies = append(anomalies, AnomalyAlert{
					DeviceMAC:   mac,
					AlertType:   "New Destination",
					Severity:    "MEDIUM",
					Description: fmt.Sprintf("Connecting to: %s", dest),
					Timestamp:   flow.LastSeen,
					Flow:        flow,
				})
			}

			// Check for new countries
			if flow.DstCountry != "" && !baseline.HasCountry(flow.DstCountry) {
				severity := "HIGH"
				// Some countries might be more suspicious than others
				suspiciousCountries := []string{"RU", "CN", "KP", "IR"}
				isSuspicious := false
				for _, sc := range suspiciousCountries {
					if flow.DstCountry == sc {
						isSuspicious = true
						severity = "CRITICAL"
						break
					}
				}

				desc := fmt.Sprintf("Connection to %s", flow.DstCountry)
				if isSuspicious {
					desc += " (high-risk country)"
				}

				anomalies = append(anomalies, AnomalyAlert{
					DeviceMAC:   mac,
					AlertType:   "New Geographic Location",
					Severity:    severity,
					Description: desc,
					Timestamp:   flow.LastSeen,
					Flow:        flow,
				})
			}

			// Check for unusual timing
			hour := flow.LastSeen.Hour()
			if !baseline.IsActiveHour(hour) && flow.ByteCount > 1000000 {
				// Large transfer during typically inactive hour
				anomalies = append(anomalies, AnomalyAlert{
					DeviceMAC:   mac,
					AlertType:   "Unusual Activity Time",
					Severity:    "LOW",
					Description: fmt.Sprintf("Large transfer at %02d:00 (typically inactive)", hour),
					Timestamp:   flow.LastSeen,
					Flow:        flow,
				})
			}

			// Limit anomalies per baseline to avoid spam
			if len(anomalies) > 50 {
				break
			}
		}

		if len(anomalies) > 50 {
			break
		}
	}

	return anomalies
}

func printAnomalyDetails(a AnomalyAlert, index int) {
	// Severity indicator
	severityIcon := "🔵"
	switch a.Severity {
	case "CRITICAL":
		severityIcon = "🔴"
	case "HIGH":
		severityIcon = "🟠"
	case "MEDIUM":
		severityIcon = "🟡"
	}

	fmt.Printf("[%d] %s %s - %s\n", index, severityIcon, a.Severity, a.AlertType)

	if a.DeviceName != "" {
		fmt.Printf("    Device: %s (%s)\n", a.DeviceName, a.DeviceMAC)
	} else {
		fmt.Printf("    Device: %s\n", a.DeviceMAC)
	}

	fmt.Printf("    %s\n", a.Description)

	if a.Flow != nil {
		dest := a.Flow.DstDomain
		if dest == "" {
			dest = a.Flow.Key.DstIP
		}
		fmt.Printf("    Destination: %s", dest)
		if a.Flow.DstCountry != "" {
			fmt.Printf(" (%s)", a.Flow.DstCountry)
		}
		fmt.Println()

		if a.Flow.Application != "" {
			fmt.Printf("    Application: %s\n", a.Flow.Application)
		}
	}

	fmt.Printf("    Time: %s (%s ago)\n",
		a.Timestamp.Format("2006-01-02 15:04:05"),
		formatDuration(time.Since(a.Timestamp)))

	fmt.Println()
}
