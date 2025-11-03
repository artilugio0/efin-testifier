require "other_tests"
require "example_preconditions"

function test_get_example(context)
  context.counter = context.counter + 1

  local resp = http_request(context.request)
  assert_equal(resp.status_code, 200)
end

function test_get_bad_request(context)
  context.counter = context.counter + 1

  context.request.body = 'invalid'
  local resp = http_request(context.request)
  assert_equal(resp.status_code, 200) -- This will raise an error.
end
