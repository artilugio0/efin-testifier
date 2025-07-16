package liblua

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strings"
	"time"

	"github.com/artilugio0/efin-testifier/pkg/ratelimit"
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

// SetLuaPackagePath prepends the given directory to Lua's package.path.
func SetLuaPackagePath(L *lua.LState, dir string) error {
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

// ParseRequestTable converts a Lua table to an HTTPRequest struct.
func ParseRequestTable(L *lua.LState, table *lua.LTable) (HTTPRequest, error) {
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

// JsonToLua converts a JSON value to a Lua value.
func JsonToLua(L *lua.LState, value interface{}) lua.LValue {
	switch v := value.(type) {
	case map[string]interface{}:
		tbl := L.NewTable()
		for key, val := range v {
			L.SetField(tbl, key, JsonToLua(L, val))
		}
		return tbl
	case []interface{}:
		tbl := L.NewTable()
		for i, val := range v {
			L.RawSetInt(tbl, i+1, JsonToLua(L, val)) // Lua arrays are 1-based.
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

// CookieToLua converts an http.Cookie to a Lua table.
func CookieToLua(L *lua.LState, cookie *http.Cookie) *lua.LTable {
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

// RegisterCommonRuntimeFunctionsWithClient registers Lua functions with a specific HTTP client.
func RegisterCommonRuntimeFunctionsWithClient(L *lua.LState, client *ratelimit.RateLimitedClient) {
	// Register http_request function.
	L.SetGlobal("http_request", L.NewFunction(func(L *lua.LState) int {
		// Expect a table as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
			L.RaiseError("http_request expects a table argument")
			return 0
		}

		// Parse request table.
		req, err := ParseRequestTable(L, L.Get(1).(*lua.LTable))
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
		result := JsonToLua(L, data)

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
				L.Push(CookieToLua(L, cookie))
				return 1
			}
		}

		// Cookie not found, return nil.
		L.Push(lua.LNil)
		return 1
	}))
}

// RegisterRuntimeFunctions registers Lua functions with a default rate-limited client.
func RegisterCommonRuntimeFunctions(L *lua.LState, requestsPerSecond float64) {
	// Create a default rate-limited client for non-test use (though not used in main).
	baseClient := &http.Client{
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		},
	}
	rateLimitedClient := ratelimit.NewRateLimitedClient(baseClient, requestsPerSecond)
	RegisterCommonRuntimeFunctionsWithClient(L, rateLimitedClient)
}
