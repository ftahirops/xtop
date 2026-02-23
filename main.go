package main

import (
	"errors"
	"fmt"
	"os"

	"github.com/ftahirops/xtop/cmd"
)

func main() {
	if err := cmd.Run(); err != nil {
		// #36: Handle ExitCodeError without printing "Error:" noise
		var exitErr cmd.ExitCodeError
		if errors.As(err, &exitErr) {
			os.Exit(exitErr.Code)
		}
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}
}
