package cmd

import (
	"fmt"
	"os"

	"github.com/artilugio0/efin-testifier/internal/testifier"
	"github.com/spf13/cobra"
)

const (
	DefaultRequestsPerSecond float64 = 20.0
)

func NewTestifierCmd(name string) *cobra.Command {
	var requestsPerSecond float64

	var testifierCmd = &cobra.Command{
		Use:   name + " <lua_file>",
		Short: "Run Lua-based HTTP tests or a single HTTP request",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			if err := testifier.Run(args[0], requestsPerSecond); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	testifierCmd.Flags().Float64VarP(
		&requestsPerSecond,
		"rps",
		"r",
		DefaultRequestsPerSecond,
		"Maximum HTTP requests per second for tests",
	)

	return testifierCmd
}

// Execute runs the root command.
func Execute() {
	if err := NewTestifierCmd("efin-testifier").Execute(); err != nil {
		os.Exit(1)
	}
}
