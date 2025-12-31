package output

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/manifoldco/promptui"
)

// Confirm asks for confirmation.
func Confirm(message string, defaultYes bool) (bool, error) {
	// If not a TTY, return default
	if !isTerminal() {
		return defaultYes, nil
	}

	prompt := promptui.Prompt{
		Label:     message,
		IsConfirm: true,
		Default:   "y",
	}

	if !defaultYes {
		prompt.Default = "n"
	}

	result, err := prompt.Run()
	if err != nil {
		if errors.Is(err, promptui.ErrAbort) {
			return false, nil
		}
		return false, err
	}

	return strings.ToLower(result) == "y" || result == "", nil
}

// ConfirmDanger asks for confirmation for dangerous operations.
func ConfirmDanger(message string) (bool, error) {
	// If not a TTY, refuse dangerous operations
	if !isTerminal() {
		return false, fmt.Errorf("confirmation required (use --yes to skip)")
	}

	fmt.Fprintln(os.Stderr, Red("⚠ WARNING: "+message))

	prompt := promptui.Prompt{
		Label:     "Type 'yes' to confirm",
		IsConfirm: false,
	}

	result, err := prompt.Run()
	if err != nil {
		return false, err
	}

	return strings.ToLower(result) == "yes", nil
}

// PromptString asks for a string input.
func PromptString(label, defaultValue string, validate func(string) error) (string, error) {
	if !isTerminal() {
		if defaultValue != "" {
			return defaultValue, nil
		}
		return "", fmt.Errorf("%s is required", label)
	}

	prompt := promptui.Prompt{
		Label:   label,
		Default: defaultValue,
	}

	if validate != nil {
		prompt.Validate = validate
	}

	return prompt.Run()
}

// PromptPassword asks for a password input (hidden).
func PromptPassword(label string) (string, error) {
	if !isTerminal() {
		return "", fmt.Errorf("%s is required", label)
	}

	prompt := promptui.Prompt{
		Label: label,
		Mask:  '*',
	}

	return prompt.Run()
}

// PromptSelect asks the user to select from a list.
func PromptSelect(label string, items []string) (int, string, error) {
	if !isTerminal() {
		return -1, "", fmt.Errorf("interactive selection required")
	}

	prompt := promptui.Select{
		Label: label,
		Items: items,
	}

	return prompt.Run()
}

// SelectItem represents an item in a select list.
type SelectItem struct {
	Name        string
	Description string
}

// PromptSelectItem asks the user to select from a list of items with descriptions.
func PromptSelectItem(label string, items []SelectItem) (int, error) {
	if !isTerminal() {
		return -1, fmt.Errorf("interactive selection required")
	}

	templates := &promptui.SelectTemplates{
		Label:    "{{ . }}",
		Active:   "▸ {{ .Name | cyan }} - {{ .Description }}",
		Inactive: "  {{ .Name }} - {{ .Description | faint }}",
		Selected: "✓ {{ .Name | green }}",
	}

	prompt := promptui.Select{
		Label:     label,
		Items:     items,
		Templates: templates,
	}

	idx, _, err := prompt.Run()
	return idx, err
}
