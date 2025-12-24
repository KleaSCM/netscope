/**
 * Anomaly Detection Engine.
 *
 * Identifies deviations from established behavioral baselines,
 * such as volume spikes, new locations, or unusual timing.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"fmt"

	"github.com/kleaSCM/netscope/internal/models"
)

type AnomalyType string

const (
	AnomalyTypeVolume      AnomalyType = "VOLUME_SPIKE"
	AnomalyTypeNewDest     AnomalyType = "NEW_DESTINATION"
	AnomalyTypeNewApp      AnomalyType = "NEW_APPLICATION"
	AnomalyTypeNewGeo      AnomalyType = "NEW_GEOGRAPHY"
	AnomalyTypeUnusualTime AnomalyType = "UNUSUAL_TIME"
	AnomalyTypeBeaconing   AnomalyType = "BEACONING_ACTIVITY"
)

type AnomalySeverity int

const (
	SeverityLow      AnomalySeverity = 1
	SeverityMedium   AnomalySeverity = 5
	SeverityHigh     AnomalySeverity = 8
	SeverityCritical AnomalySeverity = 10
)

type Anomaly struct {
	Type        AnomalyType
	Severity    AnomalySeverity
	Description string
	Flow        *models.Flow
	Timestamp   string
}

type AnomalyDetector struct {
	volumeThresholdMultiplier float64
}

func NewAnomalyDetector() *AnomalyDetector {
	return &AnomalyDetector{
		volumeThresholdMultiplier: 5.0,
	}
}

func (ad *AnomalyDetector) Detect(flow *models.Flow, baseline *DeviceBaseline) []Anomaly {
	var anomalies []Anomaly

	if baseline == nil {
		return anomalies
	}

	// 1. Volume Spikes
	// Heuristic: Flag flows exceeding 5x the hourly average, if history > 1MB.
	avgHourly := baseline.GetAverageHourlyActivity()
	if avgHourly > 1024*1024 {
		if float64(flow.ByteCount) > avgHourly*ad.volumeThresholdMultiplier {
			anomalies = append(anomalies, Anomaly{
				Type:        AnomalyTypeVolume,
				Severity:    SeverityMedium,
				Description: fmt.Sprintf("Flow volume (%d bytes) exceeds 5x hourly average (%.0f bytes)", flow.ByteCount, avgHourly),
				Flow:        flow,
			})
		}
	}

	// 2. New Country
	if flow.DstCountry != "" && !baseline.HasCountry(flow.DstCountry) {
		anomalies = append(anomalies, Anomaly{
			Type:        AnomalyTypeNewGeo,
			Severity:    SeverityMedium,
			Description: fmt.Sprintf("Device connected to new country: %s", flow.DstCountry),
			Flow:        flow,
		})
	}

	// 3. New Application
	if flow.Application != "" && !baseline.HasApp(flow.Application) {
		if len(baseline.TypicalApps) > 5 {
			anomalies = append(anomalies, Anomaly{
				Type:        AnomalyTypeNewApp,
				Severity:    SeverityLow,
				Description: fmt.Sprintf("Device used new application: %s", flow.Application),
				Flow:        flow,
			})
		}
	}

	// 4. New Destination
	if flow.DstDomain != "" && !baseline.HasDestination(flow.DstDomain) {
		if len(baseline.TypicalDestinations) > 20 {
			anomalies = append(anomalies, Anomaly{
				Type:        AnomalyTypeNewDest,
				Severity:    SeverityLow,
				Description: fmt.Sprintf("Device visited new domain: %s", flow.DstDomain),
				Flow:        flow,
			})
		}
	}

	// 5. Unusual Time
	hour := flow.LastSeen.Hour()
	if baseline.TypicalHourlyActivity[hour] == 0 && baseline.FlowCount > 100 {
		anomalies = append(anomalies, Anomaly{
			Type:        AnomalyTypeUnusualTime,
			Severity:    SeverityLow,
			Description: fmt.Sprintf("Activity detected during typically inactive hour: %d:00", hour),
			Flow:        flow,
		})
	}

	return anomalies
}
