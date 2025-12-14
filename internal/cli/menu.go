/**
 * CLI Menu System.
 *
 * Provides a text-based user interface for navigating the application.
 * Handles user input, menu rendering, and option execution.
 *
 * Author: KleaSCM
 * Email: KleaSCM@gmail.com
 */

// this is super simple for now, i might decie to do a full GUI later

package cli

import (
	"bufio"
	"fmt"
	"os"
	"strconv"
	"strings"
)

const banner = `
╔═══════════════════════════════════════════════════════════╗
║                       NetScope v0.1                       ║
║          Network Traffic Analysis & Monitoring            ║
╚═══════════════════════════════════════════════════════════╝
`

// Returns the application banner for display at the top of screens.
func GetBanner() string {
	return banner
}

// Encapsulates the state and logic for a single CLI menu screen.
type Menu struct {
	Title   string
	Options []MenuOption
	reader  *bufio.Reader
}

// Defines a selectable item in a menu and its associated behavior.
type MenuOption struct {
	Label  string
	Action func() error
}

// Creates a new menu instance with a specified title.
func NewMenu(title string) *Menu {
	return &Menu{
		Title:   title,
		Options: make([]MenuOption, 0),
		reader:  bufio.NewReader(os.Stdin),
	}
}

// Adds an executable option to the menu's list.
func (m *Menu) AddOption(label string, action func() error) {
	m.Options = append(m.Options, MenuOption{
		Label:  label,
		Action: action,
	})
}

// Shows the menu, handles user input, and executes the selected action.
func (m *Menu) Display() error {
	for {
		ClearScreen()
		fmt.Print(banner)

		if m.Title != "" {
			fmt.Println(m.Title)
			fmt.Println(strings.Repeat("━", 60))
		}

		// Display options
		for i, opt := range m.Options {
			fmt.Printf("  %d. %s\n", i+1, opt.Label)
		}

		fmt.Printf("\nSelect option [1-%d]: ", len(m.Options))

		choice, err := m.readInt()
		if err != nil {
			fmt.Printf("\n⚠️  Invalid input. Press Enter to continue...")
			m.reader.ReadString('\n')
			continue
		}

		if choice < 1 || choice > len(m.Options) {
			fmt.Printf("\n⚠️  Invalid option. Press Enter to continue...")
			m.reader.ReadString('\n')
			continue
		}

		// Execute selected action
		selectedOption := m.Options[choice-1]

		// Special handling for Exit
		if selectedOption.Label == "Exit" {
			return nil
		}

		err = selectedOption.Action()
		if err != nil {
			fmt.Printf("\n❌ Error: %v\n", err)
			fmt.Print("Press Enter to continue...")
			m.reader.ReadString('\n')
		}
	}
}

// Displays a prompt and waits for user input.
func Prompt(message string) (string, error) {
	reader := bufio.NewReader(os.Stdin)
	fmt.Print(message)
	input, err := reader.ReadString('\n')
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(input), nil
}

// Displays a prompt and parses the input as an integer.
func PromptInt(message string) (int, error) {
	input, err := Prompt(message)
	if err != nil {
		return 0, err
	}
	return strconv.Atoi(input)
}

// Displays a yes/no prompt and returns true for 'yes'.
func PromptYesNo(message string) bool {
	input, err := Prompt(message + " (y/n): ")
	if err != nil {
		return false
	}
	input = strings.ToLower(input)
	return input == "y" || input == "yes"
}

// Displays a list of options and returns the index of the selected item.
func Select(title string, options []string) (int, error) {
	fmt.Println("\n" + title)
	fmt.Println(strings.Repeat("━", 60))

	for i, opt := range options {
		fmt.Printf("  %d. %s\n", i+1, opt)
	}

	choice, err := PromptInt(fmt.Sprintf("\nSelect [1-%d]: ", len(options)))
	if err != nil {
		return 0, err
	}

	if choice < 1 || choice > len(options) {
		return 0, fmt.Errorf("invalid selection")
	}

	return choice - 1, nil
}

// Displays a confirmation message and waits for user approval.
func Confirm(message string) bool {
	return PromptYesNo(message)
}

// Waits for the user to press the Enter key before proceeding.
func PressEnterToContinue() {
	fmt.Print("\nPress Enter to continue...")
	bufio.NewReader(os.Stdin).ReadString('\n')
}

// Displays a message followed by a pause.
func ShowMessage(message string) {
	fmt.Println("\n" + message)
	PressEnterToContinue()
}

// Clears the terminal screen using ANSI escape codes.
func ClearScreen() {
	fmt.Print("\033[H\033[2J")
}

// readInt reads an integer from the menu's reader
func (m *Menu) readInt() (int, error) {
	input, err := m.reader.ReadString('\n')
	if err != nil {
		return 0, err
	}
	input = strings.TrimSpace(input)
	return strconv.Atoi(input)
}

// Prints a formatted table of data to the console.
func Table(headers []string, rows [][]string) {
	// Determine maximum width per column for alignment
	widths := make([]int, len(headers))
	for i, h := range headers {
		widths[i] = len(h)
	}

	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) && len(cell) > widths[i] {
				widths[i] = len(cell)
			}
		}
	}

	// Render table header
	fmt.Println()
	for i, h := range headers {
		fmt.Printf("%-*s  ", widths[i], h)
	}
	fmt.Println()

	// Render divider line
	for _, w := range widths {
		fmt.Print(strings.Repeat("━", w) + "  ")
	}
	fmt.Println()

	// Render data rows
	for _, row := range rows {
		for i, cell := range row {
			if i < len(widths) {
				fmt.Printf("%-*s  ", widths[i], cell)
			}
		}
		fmt.Println()
	}
	fmt.Println()
}
