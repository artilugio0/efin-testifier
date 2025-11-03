function preconditions()
    local context = {
        counter = 0,
        request = {
            method = "GET",
            url = "https://httpbin.org/get",
            headers = {
                ["User-Agent"] = "efin-testifier/1.0"
            }
        }
    }

    return context
end

function test_example(context)
    context.counter = context.counter + 1

    local resp = http_request(context.request)
    assert_equal(resp.status_code, 200)
end

function test_another_example(context)
    context.counter = context.counter + 1

    -- Modify request for this test
    context.request.url = "https://httpbin.org/json"
    local resp = http_request(context.request)
    assert_equal(resp.status_code, 200)
end