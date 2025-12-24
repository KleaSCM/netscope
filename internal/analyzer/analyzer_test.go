/**
 * Analyzer Tests.
 *
 * Verifies the functionality of Anomaly Detection, Privacy Scanning,
 * and Pattern Matching engines.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"testing"
	"time"

	"github.com/kleaSCM/netscope/internal/models"
)

func TestAnomalyDetector(t *testing.T) {
	// Setup baseline
	baseline := &DeviceBaseline{
		DeviceMAC:           "00:11:22:33:44:55",
		TypicalCountries:    map[string]int{"US": 100, "JP": 50},
		TypicalApps:         map[string]int{"HTTP": 100},
		TypicalDestinations: map[string]int{"google.com": 100},
		TypicalHourlyActivity: [24]int{
			0: 0, 1: 0, 2: 0, // Inactive hours
			12: 50 * 1024 * 1024, // Active hour (50MB) -> Avg ~2MB/hr
		},
		FlowCount:    200, // Established
		TotalBytes:   50 * 1024 * 1024,
		TotalPackets: 24000,
	}

	detector := NewAnomalyDetector()

	// Test 1: No anomaly (Normal behavior)
	t.Run("NormalBehavior", func(t *testing.T) {
		flow := &models.Flow{
			ByteCount:   500000, // 0.5MB < 5 * 2MB
			DstCountry:  "US",
			Application: "HTTP",
			DstDomain:   "google.com",
			LastSeen:    time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}
		anomalies := detector.Detect(flow, baseline)
		if len(anomalies) != 0 {
			t.Errorf("Expected 0 anomalies, got %d", len(anomalies))
		}
	})

	// Test 2: Volume Spike
	t.Run("VolumeSpike", func(t *testing.T) {
		// Avg hourly is ~2MB.
		// 5x avg = 10MB.
		// Flow is 15MB -> should trigger.
		flow := &models.Flow{
			ByteCount: 15 * 1024 * 1024,
			LastSeen:  time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}
		anomalies := detector.Detect(flow, baseline)
		found := false
		for _, a := range anomalies {
			if a.Type == AnomalyTypeVolume {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected VolumeSpike anomaly")
		}
	})

	// Test 3: New Country
	t.Run("NewCountry", func(t *testing.T) {
		flow := &models.Flow{
			DstCountry: "CN", // Not in US, JP
			LastSeen:   time.Date(2023, 1, 1, 12, 0, 0, 0, time.UTC),
		}
		anomalies := detector.Detect(flow, baseline)
		found := false
		for _, a := range anomalies {
			if a.Type == AnomalyTypeNewGeo {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected NewGeography anomaly")
		}
	})

	// Test 4: Unusual Time
	t.Run("UnusualTime", func(t *testing.T) {
		flow := &models.Flow{
			ByteCount: 100,
			LastSeen:  time.Date(2023, 1, 1, 2, 0, 0, 0, time.UTC), // 2 AM is inactive
		}
		anomalies := detector.Detect(flow, baseline)
		found := false
		for _, a := range anomalies {
			if a.Type == AnomalyTypeUnusualTime {
				found = true
				break
			}
		}
		if !found {
			t.Error("Expected UnusualTime anomaly")
		}
	})
}

func TestPrivacyScanner(t *testing.T) {
	scanner := NewPrivacyScanner()

	// Test 1: Tracker Detection
	t.Run("TrackerDetection", func(t *testing.T) {
		flow := &models.Flow{
			DstDomain: "metrics.google-analytics.com",
		}
		issues := scanner.Scan(flow)
		if len(issues) == 0 {
			t.Error("Expected privacy issue for google-analytics.com")
		}
		if issues[0].Type != PrivacyIssueTracker {
			t.Errorf("Expected Tracker issue, got %v", issues[0].Type)
		}
	})

	// Test 2: Safe Domain
	t.Run("SafeDomain", func(t *testing.T) {
		flow := &models.Flow{
			DstDomain: "wikipedia.org",
		}
		issues := scanner.Scan(flow)
		if len(issues) != 0 {
			t.Error("Expected no privacy issues for wikipedia.org")
		}
	})

	// Test 3: Cleartext PII Leak
	t.Run("CleartextPII", func(t *testing.T) {
		flow := &models.Flow{
			DNSQuery: "auth_token=abcdef12345",
			Protocol: "DNS",
		}
		issues := scanner.Scan(flow)
		if len(issues) == 0 {
			t.Error("Expected PII leak detection")
		}
		if issues[0].Type != PrivacyIssueCleartext {
			t.Errorf("Expected Cleartext issue, got %v", issues[0].Type)
		}
	})
}

func TestPatternEngine(t *testing.T) {
	rules := []PatternRule{
		{Field: "DstCountry", Operator: OpEquals, Value: "RU"},
		{Field: "ByteCount", Operator: OpGreaterThan, Value: uint64(1000)},
		{Field: "DstDomain", Operator: OpContains, Value: "malware"},
	}
	engine := NewPatternEngine(rules)

	t.Run("MatchCountry", func(t *testing.T) {
		flow := &models.Flow{DstCountry: "RU"}
		if !engine.Match(flow) {
			t.Error("Expected match for DstCountry=RU")
		}
	})

	t.Run("MatchVolume", func(t *testing.T) {
		flow := &models.Flow{ByteCount: 2000}
		if !engine.Match(flow) {
			t.Error("Expected match for ByteCount > 1000")
		}
	})

	t.Run("MatchDomain", func(t *testing.T) {
		flow := &models.Flow{DstDomain: "super-malware-site.com"}
		if !engine.Match(flow) {
			t.Error("Expected match for domain containing 'malware'")
		}
	})

	t.Run("NoMatch", func(t *testing.T) {
		flow := &models.Flow{
			DstCountry: "US",
			ByteCount:  100,
			DstDomain:  "google.com",
		}
		if engine.Match(flow) {
			t.Error("Expected no match")
		}
	})
}
