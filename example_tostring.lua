require "example_preconditions"

function test_tostring(context)
  print(http_request(context.request))
end
