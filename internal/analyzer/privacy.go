/**
 * Privacy Leak Scanner.
 *
 * Scans traffic for known tracking domains and cleartext transmission
 * of potentially sensitive information.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"fmt"
	"strings"

	"github.com/kleaSCM/netscope/internal/models"
)

type PrivacyIssueType string

const (
	PrivacyIssueTracker   PrivacyIssueType = "KNOWN_TRACKER"
	PrivacyIssueCleartext PrivacyIssueType = "CLEARTEXT_DATA"
	PrivacyIssueAdware    PrivacyIssueType = "ADWARE_DOMAIN"
)

type PrivacyIssue struct {
	Type        PrivacyIssueType
	Severity    AnomalySeverity
	Description string
	Flow        *models.Flow
}

type PrivacyScanner struct {
	blockedDomains map[string]bool
	piiKeywords    []string
}

func NewPrivacyScanner() *PrivacyScanner {
	return &PrivacyScanner{
		blockedDomains: map[string]bool{
			"google-analytics.com":  true,
			"doubleclick.net":       true,
			"facebook.com":          true,
			"scorecardresearch.com": true,
			"adservice.google.com":  true,
			"criteo.com":            true,
			"appsflyer.com":         true,
			"mixpanel.com":          true,
		},
		piiKeywords: []string{
			"password=", "passwd=", "pwd=", "access_token=", "auth_token=",
			"card_number=", "cvv=", "ssn=", "email=",
		},
	}
}

func (ps *PrivacyScanner) Scan(flow *models.Flow) []PrivacyIssue {
	var issues []PrivacyIssue

	// 1. Tracker Detection
	if flow.DstDomain != "" {
		if ps.blockedDomains[flow.DstDomain] {
			issues = append(issues, PrivacyIssue{
				Type:        PrivacyIssueTracker,
				Severity:    SeverityLow,
				Description: fmt.Sprintf("Connection to known tracker: %s", flow.DstDomain),
				Flow:        flow,
			})
		} else {
			for tracker := range ps.blockedDomains {
				if strings.HasSuffix(flow.DstDomain, "."+tracker) {
					issues = append(issues, PrivacyIssue{
						Type:        PrivacyIssueTracker,
						Severity:    SeverityLow,
						Description: fmt.Sprintf("Connection to known tracker subdomain: %s", flow.DstDomain),
						Flow:        flow,
					})
					break
				}
			}
		}
	}

	// 2. Cleartext PII
	fieldsToScan := []string{flow.DNSQuery, flow.TLSSNI, flow.DstDomain}

	for _, field := range fieldsToScan {
		if field == "" {
			continue
		}

		for _, keyword := range ps.piiKeywords {
			if strings.Contains(field, keyword) {
				issues = append(issues, PrivacyIssue{
					Type:        PrivacyIssueCleartext,
					Severity:    SeverityHigh,
					Description: fmt.Sprintf("Potential cleartext PII found in metadata (%s): %s", keyword, field),
					Flow:        flow,
				})
			}
		}
	}

	return issues
}
