package testifier

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"

	"github.com/artilugio0/efin-testifier/pkg/liblua"
	"github.com/artilugio0/efin-testifier/pkg/ratelimit"
	lua "github.com/yuin/gopher-lua"
)

// testResult holds the result of a test execution.
type testResult struct {
	name string
	err  error
}

func Run(luaFile string, requestsPerSecond float64, testRegex *regexp.Regexp) error {
	// Get the absolute path of the Lua file and its directory.
	luaFileAbs, err := filepath.Abs(luaFile)
	if err != nil {
		return fmt.Errorf("Error resolving Lua file path: %v", err)
	}
	luaFileDir := filepath.Dir(luaFileAbs)

	// Initialize Lua state for loading the file and checking for tests.
	L := lua.NewState()
	defer L.Close()

	// Set package.path to include the Lua file's directory.
	if err := liblua.SetLuaPackagePath(L, luaFileDir); err != nil {
		return fmt.Errorf("Error setting Lua package path: %v", err)
	}

	// Register runtime functions for tests.
	registerRuntimeFunctions(L, requestsPerSecond)

	// Load and execute the Lua file.
	if err := L.DoFile(luaFile); err != nil {
		return fmt.Errorf("Error loading Lua file: %v", err)
	}

	// Check for test functions (functions with "test_" prefix, filtered by regex).
	testFunctions := findTestFunctions(L, testRegex)
	if len(testFunctions) > 0 {
		// Run preconditions, tests, and cleanup functions concurrently.
		return runPreconditionsAndTests(L, testFunctions, luaFile, luaFileDir, requestsPerSecond)
	} else if testRegex != nil {
		fmt.Println("No tests matched the filter")
		return nil
	}

	// If no test functions, proceed with original behavior (process request table).
	requestTable := L.GetGlobal("request")
	if requestTable.Type() != lua.LTTable {
		return fmt.Errorf("Error: Lua file must export a 'request' table")
	}

	// Convert Lua table to HTTPRequest struct.
	req, err := liblua.HTTPRequestFromTable(L, requestTable.(*lua.LTable))
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	// Create HTTP request.
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return fmt.Errorf("Error creating HTTP request: %v", err)
	}

	// Set headers.
	for _, h := range req.Headers {
		httpReq.Header.Add(h.Name, h.Value)
	}

	// Create HTTP client that does not follow redirects (no rate limiting for non-test case).
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Make HTTP request.
	resp, err := client.Do(httpReq)
	if err != nil {
		return fmt.Errorf("Error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	// Print raw HTTP response.
	fmt.Printf("HTTP/%s %s\n", resp.Proto, resp.Status)
	for key, values := range resp.Header {
		for _, value := range values {
			fmt.Printf("%s: %s\n", key, value)
		}
	}
	fmt.Println()
	if _, err := io.Copy(os.Stdout, resp.Body); err != nil {
		return fmt.Errorf("Error reading response body: %v", err)
	}

	return nil
}

// findTestFunctions returns a list of global function names starting with "test_" that match the regex (if provided).
func findTestFunctions(L *lua.LState, testRegex *regexp.Regexp) []string {
	var tests []string
	L.ForEach(L.G.Global, func(key, value lua.LValue) {
		if key.Type() == lua.LTString && value.Type() == lua.LTFunction {
			name := string(key.(lua.LString))
			if strings.HasPrefix(name, "test_") {
				if testRegex == nil || testRegex.MatchString(name) {
					tests = append(tests, name)
				}
			}
		}
	})
	return tests
}

// runPreconditionsAndTests runs the preconditions function, tests, and cleanup functions concurrently.
func runPreconditionsAndTests(L *lua.LState, testNames []string, luaFile string, luaFileDir string, requestsPerSecond float64) error {
	// Check for preconditions function.
	var context *lua.LTable
	cleanupFunctionLock := sync.Mutex{}
	cleanupFunctions := []*lua.LFunction{}
	preconditions := L.GetGlobal("preconditions")
	if preconditions.Type() == lua.LTFunction {
		// Call preconditions.
		err := L.CallByParam(lua.P{
			Fn:      preconditions,
			NRet:    1,
			Protect: true,
		}, nil)
		if err != nil {
			return err
		}
		// Check if preconditions returned a table.
		if L.GetTop() > 0 {
			result := L.Get(-1)
			if result.Type() == lua.LTTable {
				context = result.(*lua.LTable)
			}
			L.Pop(1)
		}
		// Collect cleanup functions from preconditions.
		cleanupTests := L.GetGlobal("_cleanup_functions")
		if cleanupTests.Type() == lua.LTTable {
			cleanupTests.(*lua.LTable).ForEach(func(_, value lua.LValue) {
				if value.Type() == lua.LTFunction {
					cleanupFunctionLock.Lock()
					cleanupFunctions = append(cleanupFunctions, value.(*lua.LFunction))
					cleanupFunctionLock.Unlock()
				}
			})
		}
	}

	// Channel to collect test results.
	results := make(chan testResult, len(testNames))
	var wg sync.WaitGroup

	// Create a shared rate-limited client for tests.
	baseClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rateLimitedClient := ratelimit.NewRateLimitedClient(baseClient, requestsPerSecond)

	dynamicTestFunctionLock := sync.Mutex{}
	dynamicTestFunction := map[string]*lua.LFunction{}

	// Variables to track test results for summary
	var staticResults []testResult
	var dynamicResults []testResult

	// Run each static test concurrently.
	for _, name := range testNames {
		wg.Add(1)
		go func(testName string) {
			defer wg.Done()

			// Create a new Lua state for this test.
			LTest := lua.NewState()
			defer LTest.Close()

			// Set package.path for this Lua state.
			if err := liblua.SetLuaPackagePath(LTest, luaFileDir); err != nil {
				results <- testResult{name: testName, err: fmt.Errorf("error setting Lua package path: %v", err)}
				return
			}

			// Register runtime functions with the shared rate-limited client.
			registerRuntimeFunctionsWithClient(LTest, rateLimitedClient)

			// Load and execute the Lua file in the new state.
			if err := LTest.DoFile(luaFile); err != nil {
				results <- testResult{name: testName, err: fmt.Errorf("error loading Lua file: %v", err)}
				return
			}

			// Get the test function.
			fn := LTest.GetGlobal(testName)
			if fn.Type() != lua.LTFunction {
				results <- testResult{name: testName, err: fmt.Errorf("test function %s not found", testName)}
				return
			}

			// Prepare arguments (deep-copied context if exists).
			var args []lua.LValue
			if context != nil {
				args = append(args, deepCopyTable(LTest, context))
			}

			// Run the test.
			err := LTest.CallByParam(lua.P{
				Fn:      fn,
				NRet:    0,
				Protect: true,
			}, args...)
			results <- testResult{name: testName, err: err}

			// Collect dynamic tests from this test.
			dynamicTests := LTest.GetGlobal("_dynamic_tests")
			if dynamicTests.Type() == lua.LTTable {
				dynamicTests.(*lua.LTable).ForEach(func(name lua.LValue, f lua.LValue) {
					if name.Type() == lua.LTString && f.Type() == lua.LTFunction {
						dynamicTestFunctionLock.Lock()
						dynamicTestFunction[testName+"__"+string(name.(lua.LString))] = f.(*lua.LFunction)
						dynamicTestFunctionLock.Unlock()
					}
				})
			}

			// Collect cleanup functions from this test.
			cleanupTests := LTest.GetGlobal("_cleanup_functions")
			if cleanupTests.Type() == lua.LTTable {
				cleanupTests.(*lua.LTable).ForEach(func(_, value lua.LValue) {
					if value.Type() == lua.LTFunction {
						cleanupFunctionLock.Lock()
						cleanupFunctions = append(cleanupFunctions, value.(*lua.LFunction))
						cleanupFunctionLock.Unlock()
					}
				})
			}
		}(name)
	}

	// Wait for all static tests to complete and close the results channel.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect static test results in order.
	for result := range results {
		fmt.Printf("Running %s... ", result.name)
		if result.err != nil {
			fmt.Printf("FAILED: %v\n", result.err)
		} else {
			fmt.Println("PASSED")
		}
		staticResults = append(staticResults, result)
	}

	// Run dynamic tests concurrently.
	dynResults := make(chan testResult, len(dynamicTestFunction))
	var dynWg sync.WaitGroup

	for testName, fn := range dynamicTestFunction {
		dynWg.Add(1)
		go func(testName string, fn *lua.LFunction) {
			defer dynWg.Done()

			// Create a new Lua state for this test.
			LTest := lua.NewState()
			defer LTest.Close()

			// Set package.path for this Lua state.
			if err := liblua.SetLuaPackagePath(LTest, luaFileDir); err != nil {
				dynResults <- testResult{name: testName, err: fmt.Errorf("error setting Lua package path: %v", err)}
				return
			}

			// Register runtime functions with the shared rate-limited client.
			registerRuntimeFunctionsWithClient(LTest, rateLimitedClient)

			// Load and execute the Lua file in the new state.
			if err := LTest.DoFile(luaFile); err != nil {
				dynResults <- testResult{name: testName, err: fmt.Errorf("error loading Lua file: %v", err)}
				return
			}

			// Prepare arguments (deep-copied context if exists).
			var args []lua.LValue
			if context != nil {
				args = append(args, deepCopyTable(LTest, context))
			}

			// Run the test.
			err := LTest.CallByParam(lua.P{
				Fn:      fn,
				NRet:    0,
				Protect: true,
			}, args...)
			dynResults <- testResult{name: testName, err: err}

			// Collect cleanup functions from dynamic tests.
			cleanupTests := LTest.GetGlobal("_cleanup_functions")
			if cleanupTests.Type() == lua.LTTable {
				cleanupTests.(*lua.LTable).ForEach(func(_, value lua.LValue) {
					if value.Type() == lua.LTFunction {
						cleanupFunctionLock.Lock()
						cleanupFunctions = append(cleanupFunctions, value.(*lua.LFunction))
						cleanupFunctionLock.Unlock()
					}
				})
			}
		}(testName, fn)
	}

	// Wait for all dynamic tests to complete and close the results channel.
	go func() {
		dynWg.Wait()
		close(dynResults)
	}()

	// Collect and print dynamic test results in order.
	for result := range dynResults {
		fmt.Printf("Running %s... ", result.name)
		if result.err != nil {
			fmt.Printf("FAILED: %v\n", result.err)
		} else {
			fmt.Println("PASSED")
		}
		dynamicResults = append(dynamicResults, result)
	}

	// Run cleanup functions concurrently.
	cleanupResults := make(chan testResult, len(cleanupFunctions))
	var cleanupWg sync.WaitGroup

	for i, fn := range cleanupFunctions {
		cleanupWg.Add(1)
		go func(cleanupIndex int, fn *lua.LFunction) {
			defer cleanupWg.Done()

			// Create a new Lua state for this cleanup function.
			LCleanup := lua.NewState()
			defer LCleanup.Close()

			// Set package.path for this Lua state.
			if err := liblua.SetLuaPackagePath(LCleanup, luaFileDir); err != nil {
				cleanupResults <- testResult{name: fmt.Sprintf("cleanup_%d", cleanupIndex+1), err: fmt.Errorf("error setting Lua package path: %v", err)}
				return
			}

			// Register runtime functions (in case cleanup needs them).
			registerRuntimeFunctionsWithClient(LCleanup, rateLimitedClient)

			// Load the Lua file to ensure any necessary globals are available.
			if err := LCleanup.DoFile(luaFile); err != nil {
				cleanupResults <- testResult{name: fmt.Sprintf("cleanup_%d", cleanupIndex+1), err: fmt.Errorf("error loading Lua file: %v", err)}
				return
			}

			// Prepare arguments (deep-copied context if exists).
			var args []lua.LValue
			if context != nil {
				args = append(args, deepCopyTable(LCleanup, context))
			}

			// Run the cleanup function.
			err := LCleanup.CallByParam(lua.P{
				Fn:      fn,
				NRet:    0,
				Protect: true,
			}, args...)
			cleanupResults <- testResult{name: fmt.Sprintf("cleanup_%d", cleanupIndex+1), err: err}
		}(i, fn)
	}

	// Wait for all cleanup functions to complete and close the results channel.
	go func() {
		cleanupWg.Wait()
		close(cleanupResults)
	}()

	// Collect and print cleanup results in order.
	for result := range cleanupResults {
		fmt.Printf("Running %s... ", result.name)
		if result.err != nil {
			fmt.Printf("FAILED: %v\n", result.err)
		} else {
			fmt.Println("PASSED")
		}
	}

	// Print test summary (excluding cleanup functions)
	totalTests := len(staticResults) + len(dynamicResults)
	passedTests := 0
	for _, result := range staticResults {
		if result.err == nil {
			passedTests++
		}
	}
	for _, result := range dynamicResults {
		if result.err == nil {
			passedTests++
		}
	}
	failedTests := totalTests - passedTests

	fmt.Printf("\nTest Summary:\n")
	fmt.Printf("Total Tests: %d\n", totalTests)
	fmt.Printf("Tests Passed: %d\n", passedTests)
	fmt.Printf("Tests Failed: %d\n", failedTests)

	return nil
}

// registerRuntimeFunctionsWithClient registers Lua functions with a specific HTTP client.
func registerRuntimeFunctionsWithClient(L *lua.LState, client *ratelimit.RateLimitedClient) {
	liblua.RegisterCommonRuntimeFunctionsWithClient(L, client)

	// Register assert_equal function.
	L.SetGlobal("assert_equal", L.NewFunction(func(L *lua.LState) int {
		if L.GetTop() != 2 {
			L.RaiseError("assert_equal expects two arguments")
			return 0
		}
		actual := L.Get(1)
		expected := L.Get(2)
		if actual.String() != expected.String() {
			L.RaiseError("Assertion failed: expected %v, got %v", expected, actual)
		}
		return 0
	}))

	// Register register_test function.
	L.SetGlobal("register_test", L.NewFunction(func(L *lua.LState) int {
		// Check argument count and types
		if L.GetTop() != 2 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTFunction {
			L.RaiseError("register_test expects a string and a function")
			return 0
		}

		// Extract test name and function
		testName := string(L.Get(1).(lua.LString))
		testFunc := L.Get(2).(*lua.LFunction)

		// Get or create _dynamic_tests table to track test names
		dynamicTests := L.GetGlobal("_dynamic_tests")
		if dynamicTests.Type() == lua.LTNil {
			dynamicTests = L.NewTable()
			L.SetGlobal("_dynamic_tests", dynamicTests)
		}

		// Add test name to _dynamic_tests table
		L.SetField(dynamicTests.(*lua.LTable), testName, testFunc)
		return 0
	}))

	// Register register_cleanup function.
	L.SetGlobal("register_cleanup", L.NewFunction(func(L *lua.LState) int {
		// Check argument count and types
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTFunction {
			L.RaiseError("register_cleanup expects a function")
			return 0
		}

		// Extract cleanup function
		cleanupFunc := L.Get(1).(*lua.LFunction)

		// Get or create _cleanup_functions table to track cleanup functions
		cleanupFunctions := L.GetGlobal("_cleanup_functions")
		if cleanupFunctions.Type() == lua.LTNil {
			cleanupFunctions = L.NewTable()
			L.SetGlobal("_cleanup_functions", cleanupFunctions)
		}

		// Append cleanup function to _cleanup_functions table
		cleanupFunctions.(*lua.LTable).Append(cleanupFunc)
		return 0
	}))
}

// registerRuntimeFunctions registers Lua functions with a default rate-limited client.
func registerRuntimeFunctions(L *lua.LState, requestsPerSecond float64) {
	// Create a default rate-limited client for non-test use (though not used in main).
	baseClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rateLimitedClient := ratelimit.NewRateLimitedClient(baseClient, requestsPerSecond)
	registerRuntimeFunctionsWithClient(L, rateLimitedClient)
}

// deepCopyTable creates a deep copy of a Lua table.
func deepCopyTable(L *lua.LState, table *lua.LTable) *lua.LTable {
	newTable := L.NewTable()
	table.ForEach(func(key, value lua.LValue) {
		if value.Type() == lua.LTTable {
			// Recursively copy nested tables.
			L.SetTable(newTable, key, deepCopyTable(L, value.(*lua.LTable)))
		} else {
			L.SetTable(newTable, key, value)
		}
	})
	return newTable
}
