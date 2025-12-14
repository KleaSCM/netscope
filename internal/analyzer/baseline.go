/**
 * Behavioral Baseline Tracking.
 *
 * Learns normal behavior patterns for each device to enable
 * anomaly detection and security monitoring.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"sync"
	"time"

	"github.com/kleaSCM/netscope/internal/models"
)

// DeviceBaseline represents learned normal behavior for a device.
type DeviceBaseline struct {
	DeviceMAC             string
	FirstSeen             time.Time
	LastUpdated           time.Time
	FlowCount             int
	TypicalApps           map[string]int // app -> frequency
	TypicalDestinations   map[string]int // domain -> frequency
	TypicalTrafficClasses map[string]int // class -> frequency
	TypicalCountries      map[string]int // country -> frequency
	TypicalHourlyActivity [24]int        // traffic volume per hour
	TotalBytes            uint64
	TotalPackets          uint64
}

// BaselineTracker manages behavioral baselines for all devices.
type BaselineTracker struct {
	baselines           map[string]*DeviceBaseline // deviceMAC -> baseline
	minFlowsForBaseline int                        // Minimum flows to establish baseline
	mu                  sync.RWMutex
}

// Creates a new baseline tracker with configurable minimum flows threshold.
// minFlows determines how many flows are needed before baseline is considered established.
func NewBaselineTracker(minFlows int) *BaselineTracker {
	if minFlows == 0 {
		minFlows = 100 // Default: 100 flows
	}
	return &BaselineTracker{
		baselines:           make(map[string]*DeviceBaseline),
		minFlowsForBaseline: minFlows,
	}
}

// Incrementally updates the baseline for a device based on a new flow.
// This is called for every flow to continuously learn device behavior.
func (bt *BaselineTracker) UpdateBaseline(deviceMAC string, flow *models.Flow) {
	if flow == nil || deviceMAC == "" {
		return
	}

	bt.mu.Lock()
	defer bt.mu.Unlock()

	// Get or create baseline
	baseline, ok := bt.baselines[deviceMAC]
	if !ok {
		baseline = &DeviceBaseline{
			DeviceMAC:             deviceMAC,
			FirstSeen:             flow.FirstSeen,
			TypicalApps:           make(map[string]int),
			TypicalDestinations:   make(map[string]int),
			TypicalTrafficClasses: make(map[string]int),
			TypicalCountries:      make(map[string]int),
		}
		bt.baselines[deviceMAC] = baseline
	}

	// Update baseline
	baseline.LastUpdated = time.Now()
	baseline.FlowCount++
	baseline.TotalBytes += flow.ByteCount
	baseline.TotalPackets += flow.PacketCount

	// Track applications
	if flow.Application != "" {
		baseline.TypicalApps[flow.Application]++
	}

	// Track destinations
	if flow.DstDomain != "" {
		baseline.TypicalDestinations[flow.DstDomain]++
	} else if flow.Key.DstIP != "" {
		baseline.TypicalDestinations[flow.Key.DstIP]++
	}

	// Track traffic classes
	if flow.TrafficClass != "" {
		baseline.TypicalTrafficClasses[flow.TrafficClass]++
	}

	// Track countries
	if flow.DstCountry != "" {
		baseline.TypicalCountries[flow.DstCountry]++
	}

	// Track hourly activity
	hour := flow.LastSeen.Hour()
	baseline.TypicalHourlyActivity[hour]++
}

// Retrieves the baseline for a device to enable anomaly detection.
// Returns nil if no baseline exists.
func (bt *BaselineTracker) GetBaseline(deviceMAC string) *DeviceBaseline {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	return bt.baselines[deviceMAC]
}

// Checks if a device's baseline is reliable enough for anomaly detection.
// Baseline is considered established after minimum flow count is reached.
func (bt *BaselineTracker) IsEstablished(deviceMAC string) bool {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	baseline, ok := bt.baselines[deviceMAC]
	if !ok {
		return false
	}

	return baseline.FlowCount >= bt.minFlowsForBaseline
}

// Returns all device baselines for reporting and analysis.
func (bt *BaselineTracker) GetAllBaselines() map[string]*DeviceBaseline {
	bt.mu.RLock()
	defer bt.mu.RUnlock()

	// Return a copy to avoid race conditions
	baselines := make(map[string]*DeviceBaseline, len(bt.baselines))
	for k, v := range bt.baselines {
		baselines[k] = v
	}
	return baselines
}

// Checks if an application is in the device's baseline to detect new apps.
// Returns true if the app has been seen before.
func (baseline *DeviceBaseline) HasApp(app string) bool {
	if baseline == nil || app == "" {
		return false
	}
	_, ok := baseline.TypicalApps[app]
	return ok
}

// Checks if a destination is in the device's baseline to detect unusual connections.
func (baseline *DeviceBaseline) HasDestination(dest string) bool {
	if baseline == nil || dest == "" {
		return false
	}
	_, ok := baseline.TypicalDestinations[dest]
	return ok
}

// Checks if a country is in the device's baseline to detect geographic anomalies.
func (baseline *DeviceBaseline) HasCountry(country string) bool {
	if baseline == nil || country == "" {
		return false
	}
	_, ok := baseline.TypicalCountries[country]
	return ok
}

// Returns the average traffic volume per hour for volume spike detection.
func (baseline *DeviceBaseline) GetAverageHourlyActivity() float64 {
	if baseline == nil || baseline.FlowCount == 0 {
		return 0
	}

	total := 0
	for _, count := range baseline.TypicalHourlyActivity {
		total += count
	}

	return float64(total) / 24.0
}

// Checks if a given hour is typically active for this device to detect unusual timing.
// Returns true if the hour has above-average activity.
func (baseline *DeviceBaseline) IsActiveHour(hour int) bool {
	if baseline == nil || hour < 0 || hour > 23 {
		return false
	}

	avg := baseline.GetAverageHourlyActivity()
	return float64(baseline.TypicalHourlyActivity[hour]) > avg
}
