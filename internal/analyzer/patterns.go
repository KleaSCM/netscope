/**
 * Pattern Matching Engine.
 *
 * flexible engine to match network flows against user-defined rules
 * or signatures.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package analyzer

import (
	"regexp"
	"strings"

	"github.com/kleaSCM/netscope/internal/models"
)

// PatternOperator defines the comparison operation.
type PatternOperator string

const (
	OpEquals      PatternOperator = "EQUALS"
	OpContains    PatternOperator = "CONTAINS"
	OpStartsWith  PatternOperator = "STARTS_WITH"
	OpEndsWith    PatternOperator = "ENDS_WITH"
	OpRegex       PatternOperator = "REGEX"
	OpGreaterThan PatternOperator = "GREATER_THAN"
)

// PatternRule defines a single matching criterion.
type PatternRule struct {
	Field    string      // e.g., "DstCountry", "ByteCount"
	Operator PatternOperator
	Value    interface{}
}

// PatternEngine executes rules against flows.
type PatternEngine struct {
	rules []PatternRule
}

// NewPatternEngine creates an engine with a set of rules.
func NewPatternEngine(rules []PatternRule) *PatternEngine {
	return &PatternEngine{
		rules: rules,
	}
}

// Match checks if the flow matches ANY of the rules (OR logic for this simple version).
// Returns true if a match is found.
func (pe *PatternEngine) Match(flow *models.Flow) bool {
	for _, rule := range pe.rules {
		if checkRule(flow, rule) {
			return true
		}
	}
	return false
}

// checkRule evaluates a single rule against a flow using reflection-like manual mapping.
func checkRule(flow *models.Flow, rule PatternRule) bool {
	// 1. Get field value
	var fieldValue interface{}

	switch rule.Field {
	case "DstDomain":
		fieldValue = flow.DstDomain
	case "DstCountry":
		fieldValue = flow.DstCountry
	case "Application":
		fieldValue = flow.Application
	case "Protocol":
		fieldValue = flow.Protocol
	case "JA3":
		fieldValue = flow.JA3
	case "ByteCount":
		fieldValue = flow.ByteCount
	default:
		// Unsupported field
		return false
	}

	// 2. Compare
	switch rule.Operator {
	case OpEquals:
		return fieldValue == rule.Value

	case OpContains:
		if strVal, ok := fieldValue.(string); ok {
			if target, ok := rule.Value.(string); ok {
				return strings.Contains(strVal, target)
			}
		}

	case OpStartsWith:
		if strVal, ok := fieldValue.(string); ok {
			if target, ok := rule.Value.(string); ok {
				return strings.HasPrefix(strVal, target)
			}
		}

	case OpEndsWith:
		if strVal, ok := fieldValue.(string); ok {
			if target, ok := rule.Value.(string); ok {
				return strings.HasSuffix(strVal, target)
			}
		}

	case OpRegex:
		if strVal, ok := fieldValue.(string); ok {
			if pattern, ok := rule.Value.(string); ok {
				match, _ := regexp.MatchString(pattern, strVal)
				return match
			}
		}

	case OpGreaterThan:
		// Handle numeric types (only ByteCount supported in switch above)
		if numVal, ok := fieldValue.(uint64); ok {
			// Handle target value being int/float/uint
			switch target := rule.Value.(type) {
			case int:
				return numVal > uint64(target)
			case int64:
				return numVal > uint64(target)
			case uint64:
				return numVal > target
			}
		}
	}

	return false
}
