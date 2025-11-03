require "example_preconditions"

function test_tostring(context)
  local resp = http_request(context.request)
  print("tostring", resp.__tostring)
  print(resp)
end
