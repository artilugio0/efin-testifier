package cmd

import (
	"embed"
	"fmt"
	"os"
	"regexp"

	"github.com/artilugio0/efin-testifier/internal/testifier"
	"github.com/spf13/cobra"
)

//go:embed templates/*
var templateFS embed.FS

const (
	DefaultRequestsPerSecond float64 = 20.0
)

// NewTestifierCmd creates the root command with backwards compatibility
func NewTestifierCmd(name string) *cobra.Command {
	var rootCmd = &cobra.Command{
		Use:   name,
		Short: "HTTP requests testing tool",
		Long: name + ` is a tool for running HTTP requests and tests defined in Lua scripts.

You can run Lua files directly for backwards compatibility:
  ` + name + ` example.lua

Or use explicit subcommands:
  ` + name + ` run example.lua
  ` + name + ` scaffold request my_request.lua
  ` + name + ` scaffold test my_tests.lua`,
		Args: cobra.ArbitraryArgs,
		Run: func(cmd *cobra.Command, args []string) {
			// Check if first arg is a known subcommand
			if len(args) > 0 {
				switch args[0] {
				case "run":
					runCmd := NewRunCmd()
					runCmd.SetArgs(args[1:])
					if err := runCmd.Execute(); err != nil {
						os.Exit(1)
					}
					return
				case "scaffold":
					scaffoldCmd := NewScaffoldCmd()
					scaffoldCmd.SetArgs(args[1:])
					if err := scaffoldCmd.Execute(); err != nil {
						os.Exit(1)
					}
					return
				case "help", "completion":
					// Let Cobra handle these
					return
				default:
					// Assume it's a file path - backwards compatibility
					runCmd := NewRunCmd()
					runCmd.SetArgs(args)
					if err := runCmd.Execute(); err != nil {
						os.Exit(1)
					}
					return
				}
			}
			// No args provided, show help
			cmd.Help()
		},
	}

	return rootCmd
}

// NewRunCmd creates the run subcommand for executing Lua files
func NewRunCmd() *cobra.Command {
	var requestsPerSecond float64
	var testRegex string

	var runCmd = &cobra.Command{
		Use:   "run <lua_file>",
		Short: "Run Lua-based HTTP tests or a single HTTP request",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			// Validate regex if provided
			var compiledRegex *regexp.Regexp
			if testRegex != "" {
				var err error
				compiledRegex, err = regexp.Compile(testRegex)
				if err != nil {
					fmt.Fprintf(os.Stderr, "Error: Invalid test regex pattern: %v\n", err)
					os.Exit(1)
				}
			}
			if err := testifier.Run(args[0], requestsPerSecond, compiledRegex); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
		},
	}

	runCmd.Flags().Float64VarP(
		&requestsPerSecond,
		"rps",
		"r",
		DefaultRequestsPerSecond,
		"Maximum HTTP requests per second for tests",
	)
	runCmd.Flags().StringVarP(
		&testRegex,
		"test-regex",
		"t",
		"",
		"Regex pattern to filter static test names (e.g., 'test_.*_api')",
	)

	return runCmd
}

// NewScaffoldCmd creates the scaffold parent command
func NewScaffoldCmd() *cobra.Command {
	var scaffoldCmd = &cobra.Command{
		Use:   "scaffold",
		Short: "Create Lua scaffolding files",
		Long:  `Create scaffolding files for HTTP requests or test suites.`,
	}

	scaffoldCmd.AddCommand(NewScaffoldRequestCmd())
	scaffoldCmd.AddCommand(NewScaffoldTestCmd())

	return scaffoldCmd
}

// NewScaffoldRequestCmd creates the scaffold request subcommand
func NewScaffoldRequestCmd() *cobra.Command {
	var requestCmd = &cobra.Command{
		Use:   "request <filename>",
		Short: "Create a Lua file for a single HTTP request",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			if err := createRequestScaffold(filename); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created request scaffold: %s\n", filename)
		},
	}

	return requestCmd
}

// NewScaffoldTestCmd creates the scaffold test subcommand
func NewScaffoldTestCmd() *cobra.Command {
	var testCmd = &cobra.Command{
		Use:   "test <filename>",
		Short: "Create a Lua file for HTTP tests",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			if err := createTestScaffold(filename); err != nil {
				fmt.Fprintf(os.Stderr, "Error: %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Created test scaffold: %s\n", filename)
		},
	}

	return testCmd
}

// createRequestScaffold creates a basic request Lua file
func createRequestScaffold(filename string) error {
	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("file %s already exists", filename)
	}

	templateBytes, err := templateFS.ReadFile("templates/request.lua")
	if err != nil {
		return fmt.Errorf("failed to read request template: %w", err)
	}

	return os.WriteFile(filename, templateBytes, 0644)
}

// createTestScaffold creates a basic test Lua file
func createTestScaffold(filename string) error {
	// Check if file already exists
	if _, err := os.Stat(filename); err == nil {
		return fmt.Errorf("file %s already exists", filename)
	}

	templateBytes, err := templateFS.ReadFile("templates/test.lua")
	if err != nil {
		return fmt.Errorf("failed to read test template: %w", err)
	}

	return os.WriteFile(filename, templateBytes, 0644)
}

// Execute runs the root command.
func Execute() {
	if err := NewTestifierCmd("efin-testifier").Execute(); err != nil {
		os.Exit(1)
	}
}
