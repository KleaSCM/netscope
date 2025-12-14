/**
 * MAC Address Vendor Lookup.
 *
 * Resolves MAC address OUI prefixes to manufacturer names to identify
 * the hardware vendor of network devices.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package enricher

import (
	"strings"
	"sync"
)

// VendorLookup handles MAC address to Vendor resolution.
type VendorLookup struct {
	ouiMap map[string]string
	mu     sync.RWMutex
}

// NewVendorLookup initializes the lookup service with a common list of vendors.
func NewVendorLookup() *VendorLookup {
	vl := &VendorLookup{
		ouiMap: make(map[string]string),
	}
	vl.loadDefaults()
	return vl
}

// Lookup resolves the vendor name for a given MAC address.
func (vl *VendorLookup) Lookup(mac string) string {
	// Normalize MAC: remove colons/dashes, uppercase
	cleanMac := strings.ReplaceAll(strings.ReplaceAll(strings.ToUpper(mac), ":", ""), "-", "")

	if len(cleanMac) < 6 {
		return ""
	}

	prefix := cleanMac[:6]

	vl.mu.RLock()
	defer vl.mu.RUnlock()

	if vendor, ok := vl.ouiMap[prefix]; ok {
		return vendor
	}
	return ""
}

// loadDefaults populates the map with common OUIs.
// In a real app, this would load from a file or API.
func (vl *VendorLookup) loadDefaults() {
	// Common Vendor OUIs (Sample)
	defaults := map[string]string{
		// Apple
		"000393": "Apple", "0017F2": "Apple", "001C42": "Apple", "001E52": "Apple",
		"001FA3": "Apple", "0021E9": "Apple", "002312": "Apple", "002332": "Apple",
		"00236C": "Apple", "0023DF": "Apple", "002436": "Apple", "002500": "Apple",
		"00254B": "Apple", "0025BC": "Apple", "002608": "Apple", "00264A": "Apple",
		"0026B0": "Apple", "0026BB": "Apple", "0050E4": "Apple", "00A040": "Apple",
		"040CCE": "Apple", "041552": "Apple", "041E64": "Apple", "042665": "Apple",

		// Intel
		"0002B3": "Intel", "000347": "Intel", "000423": "Intel", "000C1F": "Intel",
		"001302": "Intel", "001320": "Intel", "001372": "Intel", "0013E8": "Intel",
		"001B21": "Intel", "00215C": "Intel", "0022FB": "Intel", "002314": "Intel",

		// Cisco
		"00000C": "Cisco", "000142": "Cisco", "000143": "Cisco", "000163": "Cisco",

		// Google
		"3C5AB4": "Google", "546009": "Google", "D4F547": "Google", "F88FCA": "Google",

		// Espressif (ESP8266/ESP32 common in IoT)
		"18FE34": "Espressif", "240AC4": "Espressif", "246F28": "Espressif",
		"24A160": "Espressif", "2C3AE8": "Espressif", "30AEA4": "Espressif",

		// Raspberry Pi
		"B827EB": "Raspberry Pi", "DC:A6:32": "Raspberry Pi", "E45F01": "Raspberry Pi",

		// Ubiquiti
		"00156D": "Ubiquiti", "002722": "Ubiquiti", "0418D6": "Ubiquiti",

		// VMware
		"000569": "VMware", "000C29": "VMware", "001C14": "VMware", "005056": "VMware",
	}

	for k, v := range defaults {
		vl.ouiMap[k] = v
	}
}
