package cmd

import (
	"fmt"
	"os"

	"github.com/artilugio0/efin-testifier/internal/testifier"
	"github.com/spf13/cobra"
)

var requestsPerSecond float64

// EfinTestifierCmd represents the base command.
var EfinTestifierCmd = &cobra.Command{
	Use:   "efin-testifier <lua_file>",
	Short: "Run Lua-based HTTP tests or a single HTTP request",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		if err := testifier.Run(args[0], requestsPerSecond); err != nil {
			fmt.Fprintf(os.Stderr, "Error: %v\n", err)
			os.Exit(1)
		}
	},
}

// Execute runs the root command.
func Execute() {
	if err := EfinTestifierCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func init() {
	EfinTestifierCmd.Flags().Float64VarP(&requestsPerSecond, "rps", "r", 20.0, "Maximum HTTP requests per second for tests")
}
