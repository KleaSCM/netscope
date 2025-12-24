/**
 * Storage Interface.
 *
 * Defines the contract for persistence layers, allowing the application
 * to support multiple storage backends (SQLite, PostgreSQL, etc.) interchangeably.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package storage

import "github.com/kleaSCM/netscope/internal/models"

// Defines the interface for persisting network data.
type Storage interface {
	// Lifecycle
	Close() error
	Migrate() error

	// Devices
	SaveDevice(device *models.Device) error
	GetDeviceByMAC(mac string) (*models.Device, error)
	ListDevices() ([]*models.Device, error)

	// Flows
	SaveFlow(flow *models.Flow) error
	GetRecentFlows(limit int) ([]*models.Flow, error)

	// WiFi
	SaveAccessPoint(ap *models.AccessPoint) error
	ListAccessPoints() ([]*models.AccessPoint, error)
	SaveWiFiClient(client *models.WiFiClient) error
	ListWiFiClients() ([]*models.WiFiClient, error)
}
