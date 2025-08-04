package liblua

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"path/filepath"
	"strconv"
	"strings"
	"time"

	"github.com/artilugio0/efin-testifier/pkg/ratelimit"
	lua "github.com/yuin/gopher-lua"
)

// TODO: move these HTTP core definitions to their own package
// HTTPRequest represents the structure of an HTTP request from Lua.
type HTTPRequest struct {
	Method  string
	URL     string
	Headers []HeaderEntry
	Body    string
}

// HTTPRequestFromTable converts a Lua table to an HTTPRequest struct.
func HTTPRequestFromTable(L *lua.LState, table *lua.LTable) (HTTPRequest, error) {
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
	req.Headers = []HeaderEntry{}
	headers := L.GetField(table, "headers")
	if headers.Type() == lua.LTTable {
		headersTable := headers.(*lua.LTable)

		if headersTable.Len() > 0 {
			// Headers table is an array
			for i := range headersTable.Len() {
				keyValue, ok := headersTable.RawGetInt(i + 1).(*lua.LTable)
				if !ok {
					continue
				}
				k, ok := keyValue.RawGetInt(1).(lua.LString)
				if !ok {
					continue
				}
				v, ok := keyValue.RawGetInt(2).(lua.LString)
				if !ok {
					continue
				}

				req.Headers = append(req.Headers, HeaderEntry{
					Name:  string(k),
					Value: string(v),
				})
			}
		} else {
			// Headers table is a map
			headersTable.ForEach(func(key, value lua.LValue) {
				if key.Type() != lua.LTString {
					return
				}

				// Handle case where the header contains one values
				if value.Type() == lua.LTString {
					req.Headers = append(req.Headers, HeaderEntry{
						Name:  string(key.(lua.LString)),
						Value: string(value.(lua.LString)),
					})
					return
				}

				// Handle case where the header contains multiple values
				if value.Type() != lua.LTTable {
					return
				}

				tbl := value.(*lua.LTable)
				for i := range tbl.Len() {
					v := tbl.RawGetInt(i + 1)
					if v.Type() == lua.LTString {
						req.Headers = append(req.Headers, HeaderEntry{
							Name:  string(key.(lua.LString)),
							Value: string(v.(lua.LString)),
						})
					}
				}
			})
		}
	}

	// Get body (optional).
	body := L.GetField(table, "body")
	if body.Type() == lua.LTString {
		req.Body = string(body.(lua.LString))
	}

	return req, nil
}

// rawHTTPRequestFromTable converts a Lua table to a raw HTTP request string.
func rawHTTPRequestFromTable(L *lua.LState, table *lua.LTable) (string, error) {
	req, err := HTTPRequestFromTable(L, table)
	if err != nil {
		return "", err
	}

	u, err := url.Parse(req.URL)
	if err != nil {
		return "", err
	}

	path := u.Path
	if path == "" {
		path = "/"
	}
	if u.RawQuery != "" {
		path += "?" + u.RawQuery
	}
	if u.Fragment != "" {
		path += "#" + u.Fragment
	}

	requestLine := fmt.Sprintf("%s %s HTTP/1.1", req.Method, path)

	var headers []string
	hasHost := false
	hasContentLength := false
	for _, h := range req.Headers {
		headerLine := fmt.Sprintf("%s: %s", h.Name, h.Value)
		headers = append(headers, headerLine)

		if strings.EqualFold(h.Name, "Host") {
			hasHost = true
		}
		if strings.EqualFold(h.Name, "Content-Length") {
			hasContentLength = true
		}
	}

	if !hasHost && u.Host != "" {
		headers = append(headers, fmt.Sprintf("Host: %s", u.Host))
	}

	body := req.Body
	if !hasContentLength && body != "" {
		headers = append(headers, fmt.Sprintf("Content-Length: %d", len(body)))
	}

	headerStr := strings.Join(headers, "\n")

	raw := requestLine + "\n" + headerStr + "\n\n" + body
	return raw, nil
}

// HTTPRequestToTable converts a HTTPRequest struct to a Lua table.
func HTTPRequestToTable(L *lua.LState, req HTTPRequest) *lua.LTable {
	// Create request table.
	reqTable := L.NewTable()
	L.SetField(reqTable, "method", lua.LString(req.Method))

	// Set headers.
	host := "unknown"
	headersTable := L.NewTable()
	hts := map[string]*lua.LTable{}
	for _, h := range req.Headers {
		valuesList, ok := hts[h.Name]
		if !ok {
			valuesList = L.NewTable()
			hts[h.Name] = valuesList
			L.SetField(headersTable, h.Name, valuesList)
		}
		valuesList.Append(lua.LString(h.Value))
		if strings.EqualFold(h.Name, "Host") {
			host = h.Value
		}
	}
	L.SetField(reqTable, "url", lua.LString("https://"+host+req.URL))

	L.SetField(reqTable, "headers", headersTable)

	L.SetField(reqTable, "body", lua.LString(req.Body))

	// Set the metatable with __tostring
	mt := L.NewTable()
	mt.RawSetString("__tostring", L.NewFunction(func(L *lua.LState) int {
		table := L.CheckTable(1)

		raw, err := rawHTTPRequestFromTable(L, table)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf("Error generating raw HTTP: %v", err)))
			return 1
		}

		L.Push(lua.LString(raw))
		return 1
	}))
	L.SetMetatable(reqTable, mt)

	return reqTable
}

type HeaderEntry struct {
	Name  string
	Value string
}

// HTTPResponse represents the structure of an HTTP response to Lua.
type HTTPResponse struct {
	StatusCode int
	Headers    []HeaderEntry
	Body       string
}

// HTTPResponseToTable converts a HTTPResponse struct to a Lua table.
func HTTPResponseToTable(L *lua.LState, resp HTTPResponse) *lua.LTable {
	// Create response table.
	respTable := L.NewTable()
	L.SetField(respTable, "status_code", lua.LNumber(resp.StatusCode))

	// Set headers.
	headersTable := L.NewTable()
	hts := map[string]*lua.LTable{}
	for _, h := range resp.Headers {
		valuesList, ok := hts[h.Name]
		if !ok {
			valuesList = L.NewTable()
			hts[h.Name] = valuesList
			L.SetField(headersTable, h.Name, valuesList)
		}
		valuesList.Append(lua.LString(h.Value))
	}
	L.SetField(respTable, "headers", headersTable)

	L.SetField(respTable, "body", lua.LString(resp.Body))

	// Set metatable with __tostring
	mt := L.NewTable()
	mt.RawSetString("__tostring", L.NewFunction(func(L *lua.LState) int {
		table := L.CheckTable(1)
		raw, err := rawHTTPResponseFromTable(L, table)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf("Error generating raw HTTP response: %v", err)))
			return 1
		}
		L.Push(lua.LString(raw))
		return 1
	}))
	L.SetMetatable(respTable, mt)

	return respTable
}

// HTTPResponseFromTable converts a Lua table to an HTTPResponse struct.
func HTTPResponseFromTable(L *lua.LState, table *lua.LTable) (HTTPResponse, error) {
	var resp HTTPResponse

	// Get Status Code.
	statusCode := L.GetField(table, "status_code")
	if statusCode.Type() != lua.LTNumber {
		return resp, fmt.Errorf("'status_code' must be a number")
	}
	resp.StatusCode = int(statusCode.(lua.LNumber))

	// Get headers (optional).
	resp.Headers = []HeaderEntry{}
	headers := L.GetField(table, "headers")
	if headers.Type() == lua.LTTable {
		headersTable := headers.(*lua.LTable)

		if headersTable.Len() > 0 {
			// Headers table is an array
			for i := range headersTable.Len() {
				keyValue, ok := headersTable.RawGetInt(i + 1).(*lua.LTable)
				if !ok {
					continue
				}
				k, ok := keyValue.RawGetInt(1).(lua.LString)
				if !ok {
					continue
				}
				v, ok := keyValue.RawGetInt(2).(lua.LString)
				if !ok {
					continue
				}

				resp.Headers = append(resp.Headers, HeaderEntry{
					Name:  string(k),
					Value: string(v),
				})
			}
		} else {
			// Headers table is a map
			headersTable.ForEach(func(key, value lua.LValue) {
				if key.Type() != lua.LTString {
					return
				}

				// Handle case where the header contains one values
				if value.Type() == lua.LTString {
					resp.Headers = append(resp.Headers, HeaderEntry{
						Name:  string(key.(lua.LString)),
						Value: string(value.(lua.LString)),
					})
					return
				}

				// Handle case where the header contains multiple values
				if value.Type() != lua.LTTable {
					return
				}

				tbl := value.(*lua.LTable)
				for i := range tbl.Len() {
					v := tbl.RawGetInt(i + 1)
					if v.Type() == lua.LTString {
						resp.Headers = append(resp.Headers, HeaderEntry{
							Name:  string(key.(lua.LString)),
							Value: string(v.(lua.LString)),
						})
					}
				}
			})
		}
	}

	// Get body (optional).
	body := L.GetField(table, "body")
	if body.Type() == lua.LTString {
		resp.Body = string(body.(lua.LString))
	}

	return resp, nil
}

// rawHTTPResponseFromTable converts a Lua table to a raw HTTP response string.
func rawHTTPResponseFromTable(L *lua.LState, table *lua.LTable) (string, error) {
	var resp HTTPResponse

	// Get status_code.
	status := L.GetField(table, "status_code")
	if status.Type() != lua.LTNumber {
		return "", fmt.Errorf("'status_code' must be a number")
	}
	resp.StatusCode = int(status.(lua.LNumber))

	// Get headers (optional).
	resp.Headers = []HeaderEntry{}
	headers := L.GetField(table, "headers")
	if headers.Type() == lua.LTTable {
		headersTable := headers.(*lua.LTable)

		if headersTable.Len() > 0 {
			// Headers table is an array
			for i := range headersTable.Len() {
				keyValue, ok := headersTable.RawGetInt(i + 1).(*lua.LTable)
				if !ok {
					continue
				}
				k, ok := keyValue.RawGetInt(1).(lua.LString)
				if !ok {
					continue
				}
				v, ok := keyValue.RawGetInt(2).(lua.LString)
				if !ok {
					continue
				}

				resp.Headers = append(resp.Headers, HeaderEntry{
					Name:  string(k),
					Value: string(v),
				})
			}
		} else {
			// Headers table is a map
			headersTable.ForEach(func(key, value lua.LValue) {
				if key.Type() != lua.LTString {
					return
				}

				// Handle case where the header contains one values
				if value.Type() == lua.LTString {
					resp.Headers = append(resp.Headers, HeaderEntry{
						Name:  string(key.(lua.LString)),
						Value: string(value.(lua.LString)),
					})
					return
				}

				// Handle case where the header contains multiple values
				if value.Type() != lua.LTTable {
					return
				}

				tbl := value.(*lua.LTable)
				for i := range tbl.Len() {
					v := tbl.RawGetInt(i + 1)
					if v.Type() == lua.LTString {
						resp.Headers = append(resp.Headers, HeaderEntry{
							Name:  string(key.(lua.LString)),
							Value: string(v.(lua.LString)),
						})
					}
				}
			})
		}
	}

	// Get body (optional).
	body := L.GetField(table, "body")
	if body.Type() == lua.LTString {
		resp.Body = string(body.(lua.LString))
	}

	// Build raw response
	reason := http.StatusText(resp.StatusCode)
	responseLine := fmt.Sprintf("HTTP/1.1 %d %s", resp.StatusCode, reason)

	var headersStr []string
	hasContentLength := false
	for _, h := range resp.Headers {
		headerLine := fmt.Sprintf("%s: %s", h.Name, h.Value)
		headersStr = append(headersStr, headerLine)
		if strings.EqualFold(h.Name, "Content-Length") {
			hasContentLength = true
		}
	}

	bodyStr := resp.Body
	if !hasContentLength && bodyStr != "" {
		headersStr = append(headersStr, fmt.Sprintf("Content-Length: %d", len(bodyStr)))
	}

	headerStr := strings.Join(headersStr, "\n")

	raw := responseLine + "\n" + headerStr + "\n\n" + bodyStr
	return raw, nil
}

// asHTTPResponse converts an *http.Response to HTTPResponse.
func asHTTPResponse(resp *http.Response) (HTTPResponse, error) {
	var httpResp HTTPResponse

	// Set StatusCode
	httpResp.StatusCode = resp.StatusCode

	// Read Body
	bodyBytes, err := io.ReadAll(resp.Body)
	if err != nil {
		return httpResp, fmt.Errorf("failed to read response body: %w", err)
	}
	defer resp.Body.Close() // Ensure body is closed after reading
	httpResp.Body = string(bodyBytes)

	// Set Headers
	for name, values := range resp.Header {
		for _, value := range values {
			httpResp.Headers = append(httpResp.Headers, HeaderEntry{
				Name:  name,
				Value: value,
			})
		}
	}

	return httpResp, nil
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
		req, err := HTTPRequestFromTable(L, L.Get(1).(*lua.LTable))
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
		for _, h := range req.Headers {
			httpReq.Header.Add(h.Name, h.Value)
		}

		// Make HTTP request using the rate-limited client.
		resp, err := client.Do(httpReq)
		if err != nil {
			L.RaiseError("Error making HTTP request: %v", err)
			return 0
		}
		defer resp.Body.Close()

		httpResp, err := asHTTPResponse(resp)
		if err != nil {
			L.RaiseError("%v", err)
			return 0
		}

		respTable := HTTPResponseToTable(L, httpResp)

		// Return response table.
		L.Push(respTable)
		return 1
	}))

	L.SetGlobal("http_request_raw", L.NewFunction(func(L *lua.LState) int {
		table := L.CheckTable(1)

		raw, err := rawHTTPRequestFromTable(L, table)
		if err != nil {
			L.Push(lua.LString(fmt.Sprintf("Error generating raw HTTP: %v", err)))
			return 1
		}

		L.Push(lua.LString(raw))
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

	// Register parse_form function.
	L.SetGlobal("parse_form", L.NewFunction(func(L *lua.LState) int {
		// Expect a string as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("parse_form expects a string argument")
			return 0
		}

		// Get the form body string.
		formStr := string(L.Get(1).(lua.LString))

		// Parse the form body.
		q, err := url.ParseQuery(formStr)
		if err != nil {
			L.RaiseError("Invalid form data: %v", err)
			return 0
		}

		// Initialize root as map.
		var data interface{} = make(map[string]interface{})

		// Build the structure.
		for k, vs := range q {
			segs, err := parseFormKey(k)
			if err != nil {
				L.RaiseError("Error parsing form key: %v", err)
				return 0
			}

			var val interface{}
			if len(vs) == 1 {
				val = vs[0]
			} else {
				ival := make([]interface{}, len(vs))
				for i, v := range vs {
					ival[i] = v
				}
				val = ival
			}

			err = setRecursive(&data, segs, val)
			if err != nil {
				L.RaiseError("Error building structure: %v", err)
				return 0
			}
		}

		// Convert to Lua value.
		result := JsonToLua(L, data)

		// Return the resulting table (or other Lua value).
		L.Push(result)
		return 1
	}))

	// Register parse_url function.
	L.SetGlobal("parse_url", L.NewFunction(func(L *lua.LState) int {
		// Expect a string as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("parse_url expects a string argument")
			return 0
		}

		// Get the URL string.
		urlStr := string(L.Get(1).(lua.LString))

		// Parse the URL.
		u, err := url.Parse(urlStr)
		if err != nil {
			L.RaiseError("Invalid URL: %v", err)
			return 0
		}

		// Create a table for the URL attributes.
		t := L.NewTable()

		// Set scheme.
		t.RawSetString("scheme", lua.LString(u.Scheme))

		// Set opaque.
		t.RawSetString("opaque", lua.LString(u.Opaque))

		// Set user info if present.
		if u.User != nil {
			t.RawSetString("username", lua.LString(u.User.Username()))
			p, set := u.User.Password()
			if set {
				t.RawSetString("password", lua.LString(p))
			}
		}

		// Set host.
		t.RawSetString("host", lua.LString(u.Host))

		// Set hostname and port.
		t.RawSetString("hostname", lua.LString(u.Hostname()))
		t.RawSetString("port", lua.LString(u.Port()))

		// Set path.
		t.RawSetString("path", lua.LString(u.Path))

		// Set raw path.
		t.RawSetString("raw_path", lua.LString(u.RawPath))

		// Set force query.
		t.RawSetString("force_query", lua.LBool(u.ForceQuery))

		// Set raw query.
		t.RawSetString("raw_query", lua.LString(u.RawQuery))

		// Parse and set query as a table.
		queryTable := L.NewTable()
		for k, vs := range u.Query() {
			if len(vs) == 0 {
				continue
			} else if len(vs) == 1 {
				queryTable.RawSetString(k, lua.LString(vs[0]))
			} else {
				qt := L.NewTable()
				for i, v := range vs {
					qt.RawSetInt(i+1, lua.LString(v))
				}
				queryTable.RawSetString(k, qt)
			}
		}
		t.RawSetString("query", queryTable)

		// Set fragment.
		t.RawSetString("fragment", lua.LString(u.Fragment))

		// Set raw fragment.
		t.RawSetString("raw_fragment", lua.LString(u.RawFragment))

		// Return the table.
		L.Push(t)
		return 1
	}))

	// Register to_json function.
	L.SetGlobal("to_json", L.NewFunction(func(L *lua.LState) int {
		// Expect a table as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
			L.RaiseError("to_json expects a table argument")
			return 0
		}

		// Get the input table.
		table := L.Get(1).(*lua.LTable)

		// Convert Lua table to JSON-compatible Go value.
		data, err := luaToJson(table)
		if err != nil {
			L.RaiseError("Error converting table to JSON: %v", err)
			return 0
		}

		// Build JSON string with support for polluted keys.
		jsonStr, err := buildJSON(data)
		if err != nil {
			L.RaiseError("Error building JSON: %v", err)
			return 0
		}

		// Return the JSON string.
		L.Push(lua.LString(jsonStr))
		return 1
	}))

	// Register to_form function.
	L.SetGlobal("to_form", L.NewFunction(func(L *lua.LState) int {
		// Expect a table as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
			L.RaiseError("to_form expects a table argument")
			return 0
		}

		// Get the input table.
		table := L.Get(1)

		// Convert Lua table to JSON-compatible Go value.
		data, err := luaToJson(table)
		if err != nil {
			L.RaiseError("Error converting table: %v", err)
			return 0
		}

		// Ensure it's a map.
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			L.RaiseError("Expected table representing an object")
			return 0
		}

		// Flatten to url.Values.
		v, err := flattenToValues("", dataMap)
		if err != nil {
			L.RaiseError("%v", err)
			return 0
		}

		// Return the encoded string.
		L.Push(lua.LString(v.Encode()))
		return 1
	}))

	// Register to_url function.
	L.SetGlobal("to_url", L.NewFunction(func(L *lua.LState) int {
		// Expect a table as the first argument.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTTable {
			L.RaiseError("to_url expects a table argument")
			return 0
		}

		// Get the input table.
		t := L.Get(1).(*lua.LTable)

		// Create a url.URL struct.
		u := &url.URL{}

		// Helper function to get string from table field.
		getString := func(key string) string {
			v := t.RawGetString(key)
			if v.Type() == lua.LTString {
				return string(v.(lua.LString))
			}
			return ""
		}

		// Set scheme.
		u.Scheme = getString("scheme")

		// Set opaque.
		u.Opaque = getString("opaque")

		// Set user info.
		username := getString("username")
		password := getString("password")
		if username != "" {
			if password != "" {
				u.User = url.UserPassword(username, password)
			} else {
				u.User = url.User(username)
			}
		}

		// Set host (combine hostname and port).
		hostname := getString("hostname")
		port := getString("port")
		if hostname != "" {
			if port != "" {
				u.Host = hostname + ":" + port
			} else {
				u.Host = hostname
			}
		}

		// Set path.
		u.Path = getString("path")

		// Set force query.
		forceQuery := t.RawGetString("force_query")
		if forceQuery.Type() == lua.LTBool {
			u.ForceQuery = bool(forceQuery.(lua.LBool))
		}

		// Set query.
		query := t.RawGetString("query")
		if query.Type() == lua.LTTable {
			// Convert Lua table to Go value.
			data, err := luaToJson(query)
			if err != nil {
				L.RaiseError("Error converting query table: %v", err)
				return 0
			}

			// Ensure it's a map.
			dataMap, ok := data.(map[string]interface{})
			_, emptyArray := data.([]interface{})
			if !ok && !emptyArray {
				L.RaiseError("Expected query table representing an object")
				return 0
			}

			if !emptyArray {
				// Flatten to url.Values.
				v, err := flattenToValues("", dataMap)
				if err != nil {
					L.RaiseError("%v", err)
					return 0
				}

				u.RawQuery = v.Encode()
			}
		}

		// Set fragment.
		u.Fragment = getString("fragment")

		// Build the URL string.
		urlStr := u.String()

		// Return the URL string.
		L.Push(lua.LString(urlStr))
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

	// Register url_remove_query function.
	L.SetGlobal("url_query_delete", L.NewFunction(func(L *lua.LState) int {
		// Expect two strings: url and param_name.
		if L.GetTop() != 2 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("url_remove_query expects a url string and a param_name string")
			return 0
		}

		// Get the input url and param_name.
		urlStr := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the URL.
		u, err := url.Parse(urlStr)
		if err != nil {
			L.RaiseError("Invalid URL: %v", err)
			return 0
		}

		// Get the query parameters.
		q := u.Query()

		// Remove all instances of the param.
		q.Del(paramName)

		// Set the new raw query.
		u.RawQuery = q.Encode()

		// Get the modified URL string.
		newUrl := u.String()

		// Return the new URL.
		L.Push(lua.LString(newUrl))
		return 1
	}))

	// Register url_add_query function.
	L.SetGlobal("url_query_add", L.NewFunction(func(L *lua.LState) int {
		// Expect at least three arguments: url (string), param_name (string), and one or more values.
		if L.GetTop() < 3 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("url_add_query expects a url string, a param_name string, and one or more values")
			return 0
		}

		// Get the input url and param_name.
		urlStr := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the URL.
		u, err := url.Parse(urlStr)
		if err != nil {
			L.RaiseError("Invalid URL: %v", err)
			return 0
		}

		// Get the query parameters.
		q := u.Query()

		// Add each value as a query parameter, converting to string using Lua's tostring.
		for i := 3; i <= L.GetTop(); i++ {
			value := L.ToStringMeta(L.Get(i)).String() // Uses Lua's tostring to convert the value
			q.Add(paramName, value)
		}

		// Set the new raw query.
		u.RawQuery = q.Encode()

		// Get the modified URL string.
		newUrl := u.String()

		// Return the new URL.
		L.Push(lua.LString(newUrl))
		return 1
	}))

	// Register url_set_query function.
	L.SetGlobal("url_query_set", L.NewFunction(func(L *lua.LState) int {
		// Expect at least three arguments: url (string), param_name (string), and one or more values.
		if L.GetTop() < 3 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("url_set_query expects a url string, a param_name string, and one or more values")
			return 0
		}

		// Get the input url and param_name.
		urlStr := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the URL.
		u, err := url.Parse(urlStr)
		if err != nil {
			L.RaiseError("Invalid URL: %v", err)
			return 0
		}

		// Get the query parameters.
		q := u.Query()

		// Remove all existing occurrences of the param.
		q.Del(paramName)

		// Add each value as a query parameter, converting to string using Lua's tostring.
		for i := 3; i <= L.GetTop(); i++ {
			value := L.ToStringMeta(L.Get(i)).String() // Uses Lua's tostring to convert the value
			q.Add(paramName, value)
		}

		// Set the new raw query.
		u.RawQuery = q.Encode()

		// Get the modified URL string.
		newUrl := u.String()

		// Return the new URL.
		L.Push(lua.LString(newUrl))
		return 1
	}))

	// Register form_param_delete function.
	L.SetGlobal("form_param_delete", L.NewFunction(func(L *lua.LState) int {
		// Expect two arguments: body string and param_name string.
		if L.GetTop() != 2 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("form_param_delete expects a body string and a param_name string")
			return 0
		}

		// Get the input body and param_name.
		body := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the form body.
		q, err := url.ParseQuery(body)
		if err != nil {
			L.RaiseError("Invalid form body: %v", err)
			return 0
		}

		// Remove all instances of the param.
		q.Del(paramName)

		// Get the modified body string.
		newBody := q.Encode()

		// Return the new body.
		L.Push(lua.LString(newBody))
		return 1
	}))

	// Register form_param_add function.
	L.SetGlobal("form_param_add", L.NewFunction(func(L *lua.LState) int {
		// Expect at least three arguments: body string, param_name string, and one or more values.
		if L.GetTop() < 3 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("form_param_add expects a body string, a param_name string, and one or more values")
			return 0
		}

		// Get the input body and param_name.
		body := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the form body.
		q, err := url.ParseQuery(body)
		if err != nil {
			L.RaiseError("Invalid form body: %v", err)
			return 0
		}

		// Add each value as a form parameter, converting to string using Lua's tostring.
		for i := 3; i <= L.GetTop(); i++ {
			value := L.ToStringMeta(L.Get(i)).String() // Uses Lua's tostring to convert the value
			q.Add(paramName, value)
		}

		// Get the modified body string.
		newBody := q.Encode()

		// Return the new body.
		L.Push(lua.LString(newBody))
		return 1
	}))

	// Register form_param_set function.
	L.SetGlobal("form_param_set", L.NewFunction(func(L *lua.LState) int {
		// Expect at least three arguments: body string, param_name string, and one or more values.
		if L.GetTop() < 3 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("form_param_set expects a body string, a param_name string, and one or more values")
			return 0
		}

		// Get the input body and param_name.
		body := string(L.Get(1).(lua.LString))
		paramName := string(L.Get(2).(lua.LString))

		// Parse the form body.
		q, err := url.ParseQuery(body)
		if err != nil {
			L.RaiseError("Invalid form body: %v", err)
			return 0
		}

		// Remove all existing occurrences of the param.
		q.Del(paramName)

		// Add each value as a form parameter, converting to string using Lua's tostring.
		for i := 3; i <= L.GetTop(); i++ {
			value := L.ToStringMeta(L.Get(i)).String() // Uses Lua's tostring to convert the value
			q.Add(paramName, value)
		}

		// Get the modified body string.
		newBody := q.Encode()

		// Return the new body.
		L.Push(lua.LString(newBody))
		return 1
	}))

	// Register set_json_value function.
	L.SetGlobal("json_value_set", L.NewFunction(func(L *lua.LState) int {
		// Expect three arguments: json string, path string, and value.
		if L.GetTop() != 3 || L.Get(1).Type() != lua.LTString || L.Get(2).Type() != lua.LTString {
			L.RaiseError("set_json_value expects a json string, a path string, and a value")
			return 0
		}

		// Get the input json string and path.
		jsonStr := string(L.Get(1).(lua.LString))
		path := string(L.Get(2).(lua.LString))
		valueLua := L.Get(3)

		// Parse the JSON string.
		var data interface{}
		var err error
		if jsonStr == "" {
			data = make(map[string]interface{})
		} else {
			if err := json.Unmarshal([]byte(jsonStr), &data); err != nil {
				L.RaiseError("Invalid JSON: %v", err)
				return 0
			}
		}

		// Convert Lua value to JSON-compatible value.
		value, err := luaToJson(valueLua)
		if err != nil {
			L.RaiseError("Invalid value: %v", err)
			return 0
		}

		// Set the value at the path.
		err = setJsonPath(&data, path, value)
		if err != nil {
			L.RaiseError("Error setting path: %v", err)
			return 0
		}

		// Marshal back to JSON string.
		newJsonBytes, err := json.Marshal(data)
		if err != nil {
			L.RaiseError("Error marshaling JSON: %v", err)
			return 0
		}

		// Return the new JSON string.
		L.Push(lua.LString(string(newJsonBytes)))
		return 1
	}))

	// Register table_value_set function.
	L.SetGlobal("table_value_set", L.NewFunction(func(L *lua.LState) int {
		// Expect three arguments: table, path string, and value.
		if L.GetTop() != 3 || L.Get(1).Type() != lua.LTTable || L.Get(2).Type() != lua.LTString {
			L.RaiseError("table_value_set expects a table, a path string, and a value")
			return 0
		}

		// Get the input table and path.
		table := L.Get(1).(*lua.LTable)
		path := string(L.Get(2).(lua.LString))
		value := L.Get(3)

		// Parse the path.
		var segments []interface{}
		var err error
		if path != "" {
			segments, err = parsePath(path)
			if err != nil {
				L.RaiseError("Invalid path: %v", err)
				return 0
			}
		} else {
			L.RaiseError("path cannot be empty")
			return 0
		}

		// Set the value at the path.
		err = setTablePath(L, table, segments, value)
		if err != nil {
			L.RaiseError("Error setting path: %v", err)
			return 0
		}

		// Return the modified table.
		L.Push(table)
		return 1
	}))

	// Register json_to_form function.
	L.SetGlobal("json_to_form", L.NewFunction(func(L *lua.LState) int {
		// Expect one argument: json string.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("json_to_form expects a json string")
			return 0
		}

		// Get the input json string.
		jsonStr := string(L.Get(1).(lua.LString))

		// Parse the JSON string.
		var data interface{}
		err := json.Unmarshal([]byte(jsonStr), &data)
		if err != nil {
			L.RaiseError("Invalid JSON: %v", err)
			return 0
		}

		// Ensure it's a JSON object.
		dataMap, ok := data.(map[string]interface{})
		if !ok {
			L.RaiseError("Expected JSON object")
			return 0
		}

		// Flatten to url.Values.
		v, err := flattenToValues("", dataMap)
		if err != nil {
			L.RaiseError("Invalid JSON: %v", err)
			return 0
		}

		// Return the encoded string.
		L.Push(lua.LString(v.Encode()))
		return 1
	}))

	// Register form_to_json function.
	L.SetGlobal("form_to_json", L.NewFunction(func(L *lua.LState) int {
		// Expect one argument: form body string.
		if L.GetTop() != 1 || L.Get(1).Type() != lua.LTString {
			L.RaiseError("form_to_json expects a form body string")
			return 0
		}

		// Get the input body.
		body := string(L.Get(1).(lua.LString))

		// Parse the form body.
		q, err := url.ParseQuery(body)
		if err != nil {
			L.RaiseError("Invalid form body: %v", err)
			return 0
		}

		// Initialize root as map.
		var data interface{} = make(map[string]interface{})

		// Build the JSON structure.
		for k, vs := range q {
			segs, err := parseFormKey(k)
			if err != nil {
				L.RaiseError("%v", err)
				return 0
			}

			var val interface{}
			if len(vs) == 1 {
				val = vs[0]
			} else {
				val = vs
			}

			err = setRecursive(&data, segs, val)
			if err != nil {
				L.RaiseError("Error building JSON: %v", err)
				return 0
			}
		}

		// Marshal to JSON string.
		jsonBytes, err := json.Marshal(data)
		if err != nil {
			L.RaiseError("Error marshaling: %v", err)
			return 0
		}

		// Return the JSON string.
		L.Push(lua.LString(string(jsonBytes)))
		return 1
	}))

	// Register deep_copy function.
	L.SetGlobal("deep_copy", L.NewFunction(func(L *lua.LState) int {
		// Expect one argument: the value to copy.
		if L.GetTop() != 1 {
			L.RaiseError("deep_copy expects exactly one argument")
			return 0
		}

		// Perform deep copy of the input value.
		result := deepCopyValue(L, L.Get(1))

		// Return the copied value.
		L.Push(result)
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

func luaToJson(lv lua.LValue) (interface{}, error) {
	switch lv.Type() {
	case lua.LTNil:
		return nil, nil
	case lua.LTBool:
		return bool(lv.(lua.LBool)), nil
	case lua.LTNumber:
		n := float64(lv.(lua.LNumber))
		if i := int64(n); float64(i) == n {
			return i, nil
		}
		return n, nil
	case lua.LTString:
		return string(lv.(lua.LString)), nil
	case lua.LTTable:
		t := lv.(*lua.LTable)
		// Check if it can be treated as an array
		isArray := true
		maxIdx := 0
		t.ForEach(func(k, _ lua.LValue) {
			if k.Type() != lua.LTNumber {
				isArray = false
				return
			}
			ki := int(k.(lua.LNumber))
			if ki <= 0 {
				isArray = false
				return
			}
			if ki > maxIdx {
				maxIdx = ki
			}
		})
		if isArray && t.Len() == maxIdx {
			arr := make([]interface{}, maxIdx)
			for i := 1; i <= maxIdx; i++ {
				v := t.RawGetInt(i)
				av, err := luaToJson(v)
				if err != nil {
					return nil, err
				}
				arr[i-1] = av
			}
			return arr, nil
		} else {
			m := make(map[string]interface{})
			t.ForEach(func(k, v lua.LValue) {
				var ks string
				switch k.Type() {
				case lua.LTString:
					ks = string(k.(lua.LString))
				case lua.LTNumber:
					ks = strconv.FormatFloat(float64(k.(lua.LNumber)), 'f', -1, 64)
				default:
					// Skip non-stringifiable keys
					return
				}
				mv, err := luaToJson(v)
				if err != nil {
					return
				}
				m[ks] = mv
			})
			return m, nil
		}
	default:
		return nil, fmt.Errorf("unsupported Lua type: %s", lv.Type())
	}
}

func parsePath(path string) ([]interface{}, error) {
	var segments []interface{}
	var current strings.Builder
	i := 0
	for i < len(path) {
		c := path[i]
		if c == '.' {
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			i++
		} else if c == '[' {
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			i++
			start := i
			for i < len(path) && path[i] != ']' {
				i++
			}
			if i >= len(path) || path[i] != ']' {
				return nil, fmt.Errorf("unclosed bracket in path")
			}
			idxStr := path[start:i]
			idx, err := strconv.Atoi(idxStr)
			if err != nil {
				return nil, fmt.Errorf("invalid index: %s", idxStr)
			}
			if idx < 0 {
				return nil, fmt.Errorf("negative index not allowed")
			}
			segments = append(segments, idx)
			i++
		} else {
			current.WriteByte(c)
			i++
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments, nil
}

func setJsonPath(root *interface{}, path string, value interface{}) error {
	if path == "" {
		*root = value
		return nil
	}
	segments, err := parsePath(path)
	if err != nil {
		return err
	}
	return setRecursive(root, segments, value)
}

func setRecursive(current *interface{}, segs []interface{}, val interface{}) error {
	if len(segs) == 0 {
		*current = val
		return nil
	}
	seg := segs[0]
	switch s := seg.(type) {
	case string:
		var m map[string]interface{}
		if *current == nil {
			m = make(map[string]interface{})
			*current = m
		} else if mm, ok := (*current).(map[string]interface{}); ok {
			m = mm
		} else {
			return fmt.Errorf("expected map at key '%s', got %T", s, *current)
		}
		sub := m[s]
		err := setRecursive(&sub, segs[1:], val)
		if err != nil {
			return err
		}
		m[s] = sub
		return nil
	case int:
		var arr []interface{}
		if *current == nil {
			arr = make([]interface{}, 0)
			*current = arr
		} else if aa, ok := (*current).([]interface{}); ok {
			arr = aa
		} else {
			return fmt.Errorf("expected array at index %d, got %T", s, *current)
		}
		if s >= len(arr) {
			newLen := s + 1
			for len(arr) < newLen {
				arr = append(arr, nil)
			}
			*current = arr
		}
		sub := arr[s]
		err := setRecursive(&sub, segs[1:], val)
		if err != nil {
			return err
		}
		arr[s] = sub
		return nil
	}
	return fmt.Errorf("invalid segment type")
}

// deepCopyValue creates a deep copy of a Lua value.
func deepCopyValue(L *lua.LState, value lua.LValue) lua.LValue {
	switch value.Type() {
	case lua.LTNil, lua.LTBool, lua.LTNumber, lua.LTString:
		// Simple types are immutable and can be returned as-is.
		return value
	case lua.LTTable:
		t := value.(*lua.LTable)
		newTable := L.NewTable()

		// Copy all key-value pairs.
		t.ForEach(func(k, v lua.LValue) {
			newKey := deepCopyValue(L, k)
			newValue := deepCopyValue(L, v)
			newTable.RawSet(newKey, newValue)
		})

		// Copy metatable if it exists.
		if mt := L.GetMetatable(t); mt != lua.LNil {
			newMt := deepCopyValue(L, mt).(*lua.LTable)
			L.SetMetatable(newTable, newMt)
		}

		return newTable
	default:
		// For unsupported types (functions, userdata, etc.), return nil and raise an error.
		L.RaiseError("deep_copy does not support type: %s", value.Type())
		return lua.LNil
	}
}

// buildJSON builds a JSON string allowing duplicate keys for polluted fields.
func buildJSON(v interface{}) (string, error) {
	switch val := v.(type) {
	case map[string]interface{}:
		var pairs []jsonPair
		for k, pv := range val {
			if strings.HasPrefix(k, "__polluted__") {
				stripped := k[len("__polluted__"):]
				arr, ok := pv.([]interface{})
				if !ok {
					return "", fmt.Errorf("polluted key %s must have array value", k)
				}
				for _, item := range arr {
					if !isScalar(item) {
						return "", fmt.Errorf("polluted key %s array must contain scalars", k)
					}
					pairs = append(pairs, jsonPair{key: stripped, val: item})
				}
			} else {
				pairs = append(pairs, jsonPair{key: k, val: pv})
			}
		}
		var sb strings.Builder
		sb.WriteString("{")
		for i, p := range pairs {
			if i > 0 {
				sb.WriteString(",")
			}
			sb.WriteString(jsonQuote(p.key) + ":")
			sub, err := buildJSON(p.val)
			if err != nil {
				return "", err
			}
			sb.WriteString(sub)
		}
		sb.WriteString("}")
		return sb.String(), nil
	case []interface{}:
		var sb strings.Builder
		sb.WriteString("[")
		for i, item := range val {
			if i > 0 {
				sb.WriteString(",")
			}
			sub, err := buildJSON(item)
			if err != nil {
				return "", err
			}
			sb.WriteString(sub)
		}
		sb.WriteString("]")
		return sb.String(), nil
	case nil:
		return "null", nil
	case bool:
		if val {
			return "true", nil
		}
		return "false", nil
	case float64:
		return strconv.FormatFloat(val, 'f', -1, 64), nil
	case int64:
		return strconv.FormatInt(val, 10), nil
	case string:
		return jsonQuote(val), nil
	default:
		return "", fmt.Errorf("unsupported type: %T", v)
	}
}

type jsonPair struct {
	key string
	val interface{}
}

func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}

func isScalar(v interface{}) bool {
	switch v.(type) {
	case nil, bool, float64, int64, string:
		return true
	default:
		return false
	}
}

// flattenToValues flattens a map to url.Values, handling polluted keys.
func flattenToValues(prefix string, data map[string]interface{}) (url.Values, error) {
	v := url.Values{}
	for key, val := range data {
		if strings.HasPrefix(key, "__polluted__") {
			stripped := key[len("__polluted__"):]
			fullKey := stripped
			if prefix != "" {
				fullKey = prefix + "[" + stripped + "]"
			}
			arr, ok := val.([]interface{})
			if !ok {
				return nil, fmt.Errorf("polluted key %s must have array value", key)
			}
			for _, item := range arr {
				if !isScalar(item) {
					return nil, fmt.Errorf("polluted key %s array must contain scalars", key)
				}
				strVal := interfaceToString(item)
				v.Add(fullKey, strVal)
			}
		} else {
			fullKey := key
			if prefix != "" {
				fullKey = prefix + "[" + key + "]"
			}
			switch vv := val.(type) {
			case map[string]interface{}:
				subV, err := flattenToValues(fullKey, vv)
				if err != nil {
					return nil, err
				}
				for sk, svs := range subV {
					for _, sv := range svs {
						v.Add(sk, sv)
					}
				}
			case []interface{}:
				for i, item := range vv {
					itemKey := fullKey + "[" + strconv.Itoa(i) + "]"
					subV, err := flattenItemToValues(itemKey, item)
					if err != nil {
						return nil, err
					}
					for sk, svs := range subV {
						for _, sv := range svs {
							v.Add(sk, sv)
						}
					}
				}
			default:
				strVal := interfaceToString(val)
				v.Add(fullKey, strVal)
			}
		}
	}
	return v, nil
}

// flattenItemToValues flattens non-map items, now returning error.
func flattenItemToValues(prefix string, item interface{}) (url.Values, error) {
	v := url.Values{}
	switch it := item.(type) {
	case map[string]interface{}:
		return flattenToValues(prefix, it)
	case []interface{}:
		for i, subItem := range it {
			subKey := prefix + "[" + strconv.Itoa(i) + "]"
			subV, err := flattenItemToValues(subKey, subItem)
			if err != nil {
				return nil, err
			}
			for sk, svs := range subV {
				for _, sv := range svs {
					v.Add(sk, sv)
				}
			}
		}
		return v, nil
	case nil:
		v.Add(prefix, "")
		return v, nil
	case bool:
		v.Add(prefix, strconv.FormatBool(it))
		return v, nil
	case float64:
		v.Add(prefix, strconv.FormatFloat(it, 'f', -1, 64))
		return v, nil
	case string:
		v.Add(prefix, it)
		return v, nil
	default:
		v.Add(prefix, fmt.Sprintf("%v", it))
		return v, nil
	}
}

// interfaceToString converts an interface{} to its string representation.
func interfaceToString(val interface{}) string {
	switch v := val.(type) {
	case string:
		return v
	case float64:
		return strconv.FormatFloat(v, 'f', -1, 64)
	case int64:
		return strconv.FormatInt(v, 10)
	case bool:
		return strconv.FormatBool(v)
	case nil:
		return ""
	default:
		return fmt.Sprintf("%v", v)
	}
}

// parseFormKey parses a form key like a[b][0][c] into segments ["a", "b", 0, "c"].
func parseFormKey(key string) ([]interface{}, error) {
	var segments []interface{}
	i := 0
	var current strings.Builder
	for i < len(key) {
		c := key[i]
		if c == '[' {
			if current.Len() > 0 {
				segments = append(segments, current.String())
				current.Reset()
			}
			i++ // skip [
			start := i
			for i < len(key) && key[i] != ']' {
				i++
			}
			if i >= len(key) || key[i] != ']' {
				return nil, fmt.Errorf("unclosed bracket in key")
			}
			segStr := key[start:i]
			var seg interface{}
			if num, err := strconv.Atoi(segStr); err == nil {
				seg = num
			} else {
				seg = segStr
			}
			segments = append(segments, seg)
			i++ // skip ]
		} else {
			current.WriteByte(c)
			i++
		}
	}
	if current.Len() > 0 {
		segments = append(segments, current.String())
	}
	return segments, nil
}

// setTablePath sets the value in the Lua table based on the parsed segments.
func setTablePath(L *lua.LState, current *lua.LTable, segs []interface{}, val lua.LValue) error {
	if len(segs) == 0 {
		return nil // Should not reach here due to path check.
	}

	seg := segs[0]
	isLast := len(segs) == 1

	switch s := seg.(type) {
	case string:
		if isLast {
			current.RawSetString(s, val)
			return nil
		}
		next := current.RawGetString(s)
		var nextTable *lua.LTable
		if next.Type() == lua.LTNil {
			nextTable = L.NewTable()
			current.RawSetString(s, nextTable)
		} else if nt, ok := next.(*lua.LTable); ok {
			nextTable = nt
		} else {
			return fmt.Errorf("expected table at key '%s', got %s", s, next.Type())
		}
		return setTablePath(L, nextTable, segs[1:], val)
	case int:
		if s < 1 {
			return fmt.Errorf("invalid index '%d'", s)
		}
		if isLast {
			current.RawSetInt(s, val)
			return nil
		}
		next := current.RawGetInt(s)
		var nextTable *lua.LTable
		if next.Type() == lua.LTNil {
			nextTable = L.NewTable()
			current.RawSetInt(s, nextTable)
		} else if nt, ok := next.(*lua.LTable); ok {
			nextTable = nt
		} else {
			return fmt.Errorf("expected table at index %d, got %s", s, next.Type())
		}
		return setTablePath(L, nextTable, segs[1:], val)
	default:
		return fmt.Errorf("invalid segment type")
	}
}
