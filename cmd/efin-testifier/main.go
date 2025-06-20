package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"sort"
	"strings"
	"sync"

	lua "github.com/yuin/gopher-lua"
)

// HTTPRequest represents the structure of an HTTP request from Lua.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

// HTTPResponse represents the structure of an HTTP response to Lua.
type HTTPResponse struct {
	StatusCode int
	Headers    map[string]string
	Body       string
}

// testResult holds the result of a test execution.
type testResult struct {
	name string
	err  error
}

func main() {
	// Check if a Lua file is provided as an argument.
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: program <lua_file>")
		os.Exit(1)
	}

	luaFile := os.Args[1]

	// Initialize Lua state for loading the file and checking for tests.
	L := lua.NewState()
	defer L.Close()

	// Register runtime functions for tests.
	registerRuntimeFunctions(L)

	// Load and execute the Lua file.
	if err := L.DoFile(luaFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading Lua file: %v\n", err)
		os.Exit(1)
	}

	// Check for test functions (functions with "test_" prefix).
	testFunctions := findTestFunctions(L)
	if len(testFunctions) > 0 {
		// Run preconditions and tests concurrently.
		if err := runPreconditionsAndTests(L, testFunctions, luaFile); err != nil {
			fmt.Fprintf(os.Stderr, "Preconditions failed: %v\n", err)
			os.Exit(1)
		}
		return
	}

	// If no test functions, proceed with original behavior (process request table).
	requestTable := L.GetGlobal("request")
	if requestTable.Type() != lua.LTTable {
		fmt.Fprintln(os.Stderr, "Error: Lua file must export a 'request' table")
		os.Exit(1)
	}

	// Convert Lua table to HTTPRequest struct.
	req, err := parseRequestTable(L, requestTable.(*lua.LTable))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error: %v\n", err)
		os.Exit(1)
	}

	// Create HTTP request.
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error creating HTTP request: %v\n", err)
		os.Exit(1)
	}

	// Set headers.
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
	}

	// Create HTTP client that does not follow redirects.
	client := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}

	// Make HTTP request.
	resp, err := client.Do(httpReq)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Error making HTTP request: %v\n", err)
		os.Exit(1)
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
		fmt.Fprintf(os.Stderr, "Error reading response body: %v\n", err)
		os.Exit(1)
	}
}

// parseRequestTable converts a Lua table to an HTTPRequest struct.
func parseRequestTable(L *lua.LState, table *lua.LTable) (HTTPRequest, error) {
	var req HTTPRequest

	// Get method.
	method := L.GetField(table, "method")
	if method.Type() != lua.LTString {
		return req, fmt.Errorf("'method' must be a string")
	}
	req.Method = string(method.(lua.LString))
	if req.Method == "" {
		return req, fmt.Errorf("'method' cannot be empty")
	}

	// Get URL.
	url := L.GetField(table, "url")
	if url.Type() != lua.LTString {
		return req, fmt.Errorf("'url' must be a string")
	}
	req.URL = string(url.(lua.LString))
	if req.URL == "" {
		return req, fmt.Errorf("'url' cannot be empty")
	}

	// Get headers (optional).
	req.Headers = make(map[string]string)
	headers := L.GetField(table, "headers")
	if headers.Type() == lua.LTTable {
		headersTable := headers.(*lua.LTable)
		headersTable.ForEach(func(key, value lua.LValue) {
			if key.Type() == lua.LTString && value.Type() == lua.LTString {
				req.Headers[string(key.(lua.LString))] = string(value.(lua.LString))
			}
		})
	}

	// Get body (optional).
	body := L.GetField(table, "body")
	if body.Type() == lua.LTString {
		req.Body = string(body.(lua.LString))
	}

	return req, nil
}

// findTestFunctions returns a list of global function names starting with "test_".
func findTestFunctions(L *lua.LState) []string {
	var tests []string
	L.ForEach(L.G.Global, func(key, value lua.LValue) {
		if key.Type() == lua.LTString && value.Type() == lua.LTFunction {
			name := string(key.(lua.LString))
			if strings.HasPrefix(name, "test_") {
				tests = append(tests, name)
			}
		}
	})
	return tests
}

// runPreconditionsAndTests runs the preconditions function and tests concurrently.
func runPreconditionsAndTests(L *lua.LState, testNames []string, luaFile string) error {
	// Check for preconditions function.
	var context *lua.LTable
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
	}

	// Sort test names for consistent reporting order.
	sort.Strings(testNames)

	// Channel to collect test results.
	results := make(chan testResult, len(testNames))
	var wg sync.WaitGroup

	// Run each test concurrently.
	for _, name := range testNames {
		wg.Add(1)
		go func(testName string) {
			defer wg.Done()

			// Create a new Lua state for this test.
			LTest := lua.NewState()
			defer LTest.Close()

			// Register runtime functions.
			registerRuntimeFunctions(LTest)

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
		}(name)
	}

	// Wait for all tests to complete and close the results channel.
	go func() {
		wg.Wait()
		close(results)
	}()

	// Collect and print results in order.
	for result := range results {
		fmt.Printf("Running %s... ", result.name)
		if result.err != nil {
			fmt.Printf("FAILED: %v\n", result.err)
		} else {
			fmt.Println("PASSED")
		}
	}

	return nil
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

// jsonToLua converts a JSON value to a Lua value.
func jsonToLua(L *lua.LState, value interface{}) lua.LValue {
	switch v := value.(type) {
	case map[string]interface{}:
		tbl := L.NewTable()
		for key, val := range v {
			L.SetField(tbl, key, jsonToLua(L, val))
		}
		return tbl
	case []interface{}:
		tbl := L.NewTable()
		for i, val := range v {
			L.RawSetInt(tbl, i+1, jsonToLua(L, val)) // Lua arrays are 1-based.
		}
		return tbl
	case string:
		return lua.LString(v)
	case float64:
		return lua.LNumber(v)
	case bool:
		return lua.LBool(v)
	case nil:
		return lua.LNil
	default:
		return lua.LNil // Unsupported types return nil.
	}
}

// registerRuntimeFunctions registers Lua functions for HTTP requests, assertions, and JSON parsing.
func registerRuntimeFunctions(L *lua.LState) {
	// Register http_request function.
	L.SetGlobal("http_request", L.NewFunction(func(L *lua.LState) int {
		// Expect a table as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
			L.RaiseError("http_request expects a table argument")
			return 0
		}

		// Parse request table.
		req, err := parseRequestTable(L, L.Get(1).(*lua.LTable))
		if err != nil {
			L.RaiseError("Invalid request: %v", err)
			return 0
		}

		// Create HTTP request.
		httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
		if err != nil {
			L.RaiseError("Error creating HTTP request: %v", err)
			return 0
		}

		// Set headers.
		for k, v := range req.Headers {
			httpReq.Header.Set(k, v)
		}

		// Create HTTP client that does not follow redirects.
		client := &http.Client{
			CheckRedirect: func(req *http.Request, via []*http.Request) error {
				return http.ErrUseLastResponse
			},
		}

		// Make HTTP request.
		resp, err := client.Do(httpReq)
		if err != nil {
			L.RaiseError("Error making HTTP request: %v", err)
			return 0
		}
		defer resp.Body.Close()

		// Read response body.
		body, err := io.ReadAll(resp.Body)
		if err != nil {
			L.RaiseError("Error reading response body: %v", err)
			return 0
		}

		// Create response table.
		respTable := L.NewTable()
		L.SetField(respTable, "status_code", lua.LNumber(resp.StatusCode))

		// Set headers.
		headersTable := L.NewTable()
		for key, values := range resp.Header {
			for _, value := range values {
				L.SetField(headersTable, key, lua.LString(value))
			}
		}
		L.SetField(respTable, "headers", headersTable)

		// Set body.
		L.SetField(respTable, "body", lua.LString(body))

		// Return response table.
		L.Push(respTable)
		return 1
	}))

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

	// Register parse_json function.
	L.SetGlobal("parse_json", L.NewFunction(func(L *lua.LState) int {
		// Expect a string as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("parse_json expects a string argument")
			return 0
		}

		// Get the JSON string.
		jsonStr := string(L.Get(1).(lua.LString))

		// Parse the JSON string.
		var data interface{}
		if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
			L.RaiseError("Invalid JSON: %v", err)
			return 0
		}

		// Convert JSON to Lua value.
		result := jsonToLua(L, data)

		// Return the resulting table (or other Lua value).
		L.Push(result)
		return 1
	}))
}
