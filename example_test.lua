function preconditions()
  local context = {
    request = {
        method = "GET",
        url = "https://www.google.com",
        headers = {
            ["User-Agent"] = "Lua-Test/1.0"
        }
    }
  }

  return context
end

function test_get_example(context)
    local req = context.request
    local resp = http_request(req)
    assert_equal(resp.status_code, 200)
end

function test_post_request()
    local req = {
        method = "POST",
        url = "https://httpbin.org/post",
        body = "test data",
        headers = {
            ["Content-Type"] = "text/plain"
        }
    }
    local resp = http_request(req)
    assert_equal(resp.status_code, 200)
end

function test_get_bad_request(context)
  context.request.body = 'invalid'
  local resp = http_request(context.request)
  assert_equal(resp.status_code, 200) -- This will raise an error.
end
