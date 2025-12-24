/**
 * Query Menu Implementation.
 *
 * Provides valid options for querying captured data stored in the database,
 * such as listing devices and recent flows.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

package cli

import (
	"fmt"

	"github.com/kleaSCM/netscope/internal/storage"
)

// Displays the query data menu.
func ShowQueryMenu(store storage.Storage) error {
	menu := NewMenu("Query Data:")

	menu.AddOption("List Devices", func() error {
		return listDevices(store)
	})
	menu.AddOption("List Recent Flows", func() error {
		return listRecentFlows(store)
	})
	menu.AddOption("Back to Main Menu", func() error { return ErrExitMenu })

	return menu.Display()
}

func listDevices(store storage.Storage) error {
	ClearScreen()
	fmt.Println(GetBanner())
	fmt.Println("Registered Devices")
	fmt.Println(string(make([]rune, 60)))

	devices, err := store.ListDevices()
	if err != nil {
		return fmt.Errorf("failed to list devices: %w", err)
	}

	if len(devices) == 0 {
		fmt.Println("\nNo devices found in database.")
	} else {
		// Table Headers
		headers := []string{"ID", "IP Address", "MAC Address", "Vendor", "Last Seen"}
		rows := make([][]string, 0)

		for _, d := range devices {
			rows = append(rows, []string{
				fmt.Sprintf("%d", d.ID),
				d.IPAddress,
				d.MACAddress,
				d.Vendor,
				d.LastSeen.Format("2006-01-02 15:04:05"),
			})
		}
		Table(headers, rows)
	}

	PressEnterToContinue()
	return nil
}

func listRecentFlows(store storage.Storage) error {
	ClearScreen()
	fmt.Println(GetBanner())
	fmt.Println("Recent Flows (Top 20)")
	fmt.Println(string(make([]rune, 60)))

	flows, err := store.GetRecentFlows(20)
	if err != nil {
		return fmt.Errorf("failed to get flows: %w", err)
	}

	if len(flows) == 0 {
		fmt.Println("\nNo flows found in database.")
	} else {
		// Table Headers
		headers := []string{"Time", "Source", "Destination", "Proto", "App", "Bytes"}
		rows := make([][]string, 0)

		for _, f := range flows {
			rows = append(rows, []string{
				f.FirstSeen.Format("15:04:05"),
				fmt.Sprintf("%s:%d", f.Key.SrcIP, f.Key.SrcPort),
				fmt.Sprintf("%s:%d", f.Key.DstIP, f.Key.DstPort),
				f.Key.Protocol,
				f.Protocol, // App protocol
				fmt.Sprintf("%d", f.ByteCount),
			})
		}
		Table(headers, rows)
	}

	PressEnterToContinue()
	return nil
}
