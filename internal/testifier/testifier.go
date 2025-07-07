package testifier

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"github.com/artilugio0/efin-testifier/internal/ratelimit"
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
	if err := setLuaPackagePath(L, luaFileDir); err != nil {
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
	req, err := parseRequestTable(L, requestTable.(*lua.LTable))
	if err != nil {
		return fmt.Errorf("Error: %v", err)
	}

	// Create HTTP request.
	httpReq, err := http.NewRequest(req.Method, req.URL, strings.NewReader(req.Body))
	if err != nil {
		return fmt.Errorf("Error creating HTTP request: %v", err)
	}

	// Set headers.
	for k, v := range req.Headers {
		httpReq.Header.Set(k, v)
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

// setLuaPackagePath prepends the given directory to Lua's package.path.
func setLuaPackagePath(L *lua.LState, dir string) error {
	// Get current package.path.
	packagePath := L.GetGlobal("package").(*lua.LTable).RawGetString("path")
	pathStr := ""
	if packagePath.Type() == lua.LTString {
		pathStr = string(packagePath.(lua.LString))
	}

	// Prepend the test file's directory to package.path (e.g., "/path/to/dir/?.lua").
	newPath := filepath.Join(dir, "?.lua") + ";" + pathStr
	L.SetField(L.GetGlobal("package"), "path", lua.LString(newPath))
	return nil
}

// parseRequestTable converts a Lua table to an HTTPRequest struct.
func parseRequestTable(L *lua.LState, table *lua.LTable) (HTTPRequest, error) {
	var req HTTPRequest

	// Get method.
	method := L.GetField(table, "method")
	if method.Type() != lua.LTString {
		if method.Type() != lua.LTNil {
			return req, fmt.Errorf("'method' must be a string")
		}
		method = lua.LString("GET")
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
			if err := setLuaPackagePath(LTest, luaFileDir); err != nil {
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
			if err := setLuaPackagePath(LTest, luaFileDir); err != nil {
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
			if err := setLuaPackagePath(LCleanup, luaFileDir); err != nil {
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

// cookieToLua converts an http.Cookie to a Lua table.
func cookieToLua(L *lua.LState, cookie *http.Cookie) *lua.LTable {
	tbl := L.NewTable()
	L.SetField(tbl, "name", lua.LString(cookie.Name))
	L.SetField(tbl, "value", lua.LString(cookie.Value))
	if cookie.Path != "" {
		L.SetField(tbl, "path", lua.LString(cookie.Path))
	}
	if cookie.Domain != "" {
		L.SetField(tbl, "domain", lua.LString(cookie.Domain))
	}
	if !cookie.Expires.IsZero() {
		L.SetField(tbl, "expires", lua.LString(cookie.Expires.Format(time.RFC1123)))
	}
	L.SetField(tbl, "secure", lua.LBool(cookie.Secure))
	L.SetField(tbl, "http_only", lua.LBool(cookie.HttpOnly))
	if cookie.SameSite != http.SameSite(0) {
		sameSiteStr := ""
		switch cookie.SameSite {
		case http.SameSiteDefaultMode:
			sameSiteStr = "Default"
		case http.SameSiteLaxMode:
			sameSiteStr = "Lax"
		case http.SameSiteStrictMode:
			sameSiteStr = "Strict"
		case http.SameSiteNoneMode:
			sameSiteStr = "None"
		}
		L.SetField(tbl, "same_site", lua.LString(sameSiteStr))
	}

	L.SetField(tbl, "set_cookie_string", lua.LString(cookie.String()))
	L.SetField(tbl, "key_value", lua.LString(cookie.Name+"="+cookie.Value))

	return tbl
}

// registerRuntimeFunctionsWithClient registers Lua functions with a specific HTTP client.
func registerRuntimeFunctionsWithClient(L *lua.LState, client *ratelimit.RateLimitedClient) {
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

		// Make HTTP request using the rate-limited client.
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
			valuesList := L.NewTable()
			for _, value := range values {
				valuesList.Append(lua.LString(value))
			}
			L.SetField(headersTable, key, valuesList)
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

	// Register urlencode function.
	L.SetGlobal("urlencode", L.NewFunction(func(L *lua.LState) int {
		// Expect a string as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("urlencode expects a string argument")
			return 0
		}

		// Get the input string.
		input := string(L.Get(1).(lua.LString))

		// URL encode the string.
		encoded := url.QueryEscape(input)

		// Return the encoded string.
		L.Push(lua.LString(encoded))
		return 1
	}))

	// Register urldecode function.
	L.SetGlobal("urldecode", L.NewFunction(func(L *lua.LState) int {
		// Expect a string as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("urldecode expects a string argument")
			return 0
		}

		// Get the input string.
		input := string(L.Get(1).(lua.LString))

		// URL decode the string.
		decoded, err := url.QueryUnescape(input)
		if err != nil {
			L.RaiseError("Error decoding URL: %v", err)
			return 0
		}

		// Return the decoded string.
		L.Push(lua.LString(decoded))
		return 1
	}))

	// Register get_set_cookie function.
	L.SetGlobal("get_set_cookie", L.NewFunction(func(L *lua.LState) int {
		// Expect a table (response) and a string (cookie name) as arguments.
		if L.GetTop() != 2 || L.Get(1).Type() != lua.LTTable || L.Get(2).Type() != lua.LTString {
			L.RaiseError("get_cookie expects a response table and a cookie name string")
			return 0
		}

		// Get response table and cookie name.
		respTable := L.Get(1).(*lua.LTable)
		cookieName := string(L.Get(2).(lua.LString))

		// Get headers from response table.
		headers := L.GetField(respTable, "headers")
		if headers.Type() != lua.LTTable {
			L.RaiseError("response.headers must be a table")
			return 0
		}

		// Get Set-Cookie headers.
		setCookieHeaders := L.GetField(headers.(*lua.LTable), "Set-Cookie")
		if setCookieHeaders.Type() == lua.LTNil {
			// No Set-Cookie headers, return nil.
			L.Push(lua.LNil)
			return 1
		}

		// Parse Set-Cookie headers.
		var cookies []*http.Cookie
		if setCookieHeaders.Type() == lua.LTTable {
			// Handle multiple Set-Cookie headers as a table.
			setCookieHeaders.(*lua.LTable).ForEach(func(_, value lua.LValue) {
				if value.Type() == lua.LTString {
					cookie, err := http.ParseSetCookie(string(value.(lua.LString)))
					if err == nil {
						cookies = append(cookies, cookie)
					}
				}
			})
		} else if setCookieHeaders.Type() == lua.LTString {
			// Handle single Set-Cookie header (unlikely but possible).
			cookie, err := http.ParseSetCookie(string(setCookieHeaders.(lua.LString)))
			if err == nil {
				cookies = append(cookies, cookie)
			}
		}

		// Find the cookie with the specified name.
		for _, cookie := range cookies {
			if cookie.Name == cookieName {
				// Convert cookie to Lua table and return.
				L.Push(cookieToLua(L, cookie))
				return 1
			}
		}

		// Cookie not found, return nil.
		L.Push(lua.LNil)
		return 1
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
