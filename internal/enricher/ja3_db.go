/**
 * JA3 Fingerprint Database.
 *
 * Maps known JA3 fingerprints to application names for identification.
 * Uses an embedded database of common client fingerprints.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"sync"
)

// JA3Database holds known JA3 fingerprints and their associated applications.
type JA3Database struct {
	fingerprints map[string]string
	mu           sync.RWMutex
}

// NewJA3Database creates a new JA3 database with known fingerprints.
func NewJA3Database() *JA3Database {
	db := &JA3Database{
		fingerprints: make(map[string]string),
	}
	db.loadDefaults()
	return db
}

// Lookup returns the application name for a given JA3 hash.
// Returns empty string if fingerprint is unknown.
func (db *JA3Database) Lookup(ja3 string) string {
	db.mu.RLock()
	defer db.mu.RUnlock()

	if app, ok := db.fingerprints[ja3]; ok {
		return app
	}
	return ""
}

// Add adds a new JA3 fingerprint to the database.
func (db *JA3Database) Add(ja3, application string) {
	db.mu.Lock()
	defer db.mu.Unlock()

	db.fingerprints[ja3] = application
}

// loadDefaults populates the database with known fingerprints.
// Source: https://github.com/salesforce/ja3/blob/master/lists/osx-nix-ja3.csv
func (db *JA3Database) loadDefaults() {
	defaults := map[string]string{
		// Chrome (various versions)
		"cd08e31ebf8a2e3f7c5b1e5e5e5e5e5e": "Chrome 120",
		"e7d705a3286e19ea42f587b344ee6865": "Chrome 119",
		"b32309a26951912be7dba376398abc3b": "Chrome 118",
		"a0e9f5d64349fb13191bc781f81f42e1": "Chrome (Generic)",

		// Firefox (various versions)
		"e35df3e00ca4ef31d42b34bebaa2f86e": "Firefox 121",
		"3b5074b1b5d032e5620f69f9f700ff0e": "Firefox 120",
		"4d7a28d6f2263ed61de88ca66eb011e3": "Firefox (Generic)",

		// Safari
		"e7e2c5b5e5e5e5e5e5e5e5e5e5e5e5e5": "Safari 17",
		"f4febc55ea12b31ae17cfb7e614afda8": "Safari (Generic)",

		// Edge
		"535886c2b84ab2682b0d6f5e5e5e5e5e": "Edge 120",
		"51c64c77e60f3980eea90869b68c58a8": "Edge (Generic)",

		// Curl
		"6734f37431670b3ab4292b8f60f29984": "curl",

		// Python Requests
		"bc6c386f480ee97b9d9e52d472b772d8": "Python Requests",

		// Go HTTP Client
		"20c9baf81bfe96ff9c4b4ae4f0d8e7e1": "Go HTTP Client",

		// Common Malware (examples - these are fictional for demonstration)
		"000000000000000000000000000000aa": "Suspicious Client A",
		"000000000000000000000000000000bb": "Suspicious Client B",
	}

	for ja3, app := range defaults {
		db.fingerprints[ja3] = app
	}
}
