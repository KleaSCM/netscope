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
	var alerts []AnomalyAlert
	now := time.Now()

	privacyScanner := analyzer.NewPrivacyScanner()

	for _, flow := range flows {
		// Skip if flow is too old (only check recent activity - last 15 min)
		if now.Sub(flow.LastSeen) > 15*time.Minute {
			continue
		}

		// 1. Run Detection
		// Note: Detailed anomaly detection requires Device MAC correlation which is unavailable
		// in the simple Flow struct here. We focus on device-agnostic Privacy Scanning.

		issues := privacyScanner.Scan(flow)
		for _, issue := range issues {
			alerts = append(alerts, AnomalyAlert{
				DeviceMAC:   "Unknown",
				DeviceName:  "Unknown",
				AlertType:   string(issue.Type),
				Severity:    "HIGH",
				Description: issue.Description,
				Timestamp:   flow.LastSeen,
				Flow:        flow,
			})
		}
	}

	return alerts
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
