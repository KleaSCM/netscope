/**
 * Device Model.
 *
 * Represents a physical or virtual device on the network, tracked by
 * its MAC address and enriched with fingerprinting data.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package models

import "time"

// Represents a network device identified by MAC address.
type Device struct {
	ID            int64
	MACAddress    string
	Vendor        string
	Hostname      string
	IPAddress     string
	OSFingerprint string
	DeviceType    string
	FirstSeen     time.Time
	LastSeen      time.Time
	UserLabel     string
}
