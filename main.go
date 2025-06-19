package main

import (
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"

	lua "github.com/yuin/gopher-lua"
)

// HTTPRequest represents the structure of an HTTP request from Lua.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers map[string]string
	Body    string
}

func main() {
	// Check if a Lua file is provided as an argument.
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "Usage: program <lua_file>")
		os.Exit(1)
	}

	luaFile := os.Args[1]

	// Initialize Lua state.
	L := lua.NewState()
	defer L.Close()

	// Load and execute the Lua file.
	if err := L.DoFile(luaFile); err != nil {
		fmt.Fprintf(os.Stderr, "Error loading Lua file: %v\n", err)
		os.Exit(1)
	}

	// Get the global "request" table.
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

	// Make HTTP request.
	client := &http.Client{}
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
