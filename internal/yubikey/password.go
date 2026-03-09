package yubikey

import (
	"fmt"
	"os"

	"golang.org/x/term"
)

// ReadPassword reads a password from stdin without echoing to terminal.
func ReadPassword(prompt string) (string, error) {
	fmt.Print(prompt)
	password, err := term.ReadPassword(int(os.Stdin.Fd()))
	fmt.Println()
	if err != nil {
		return "", err
	}
	return string(password), nil
}
